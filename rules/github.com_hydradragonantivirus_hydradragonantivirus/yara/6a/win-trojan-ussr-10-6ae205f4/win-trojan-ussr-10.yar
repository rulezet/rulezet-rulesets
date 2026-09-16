rule Win_Trojan_USSR_10
{
strings:
	$a0 = { 0b80e10480f9047449b8023de85a }


condition:
	$a0
}