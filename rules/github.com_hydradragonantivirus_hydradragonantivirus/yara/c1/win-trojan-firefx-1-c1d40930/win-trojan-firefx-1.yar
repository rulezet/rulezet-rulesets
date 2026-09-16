rule Win_Trojan_FireFX_1
{
strings:
	$a0 = { 8db65201a5a5a5a5c6867c07008d96e302e84d0080be7c0705730ab43b8d96e902cd2173e8 }


condition:
	$a0
}