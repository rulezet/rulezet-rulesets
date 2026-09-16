rule Win_Trojan_Gen_110
{
strings:
	$a0 = { 2435cd21899c8f008c84910007b82425 }


condition:
	$a0
}