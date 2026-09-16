rule Win_Trojan_Polish_1
{
strings:
	$a0 = { 9501b9d3068cc3bf95010e07fcac3441aae2fa }


condition:
	$a0
}