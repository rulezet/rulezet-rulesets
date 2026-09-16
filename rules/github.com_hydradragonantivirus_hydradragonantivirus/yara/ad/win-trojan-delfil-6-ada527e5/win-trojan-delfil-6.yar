rule Win_Trojan_DelFil_6
{
strings:
	$a0 = { 64656c202573797374656d6472697665255c2a2e2a }


condition:
	$a0
}