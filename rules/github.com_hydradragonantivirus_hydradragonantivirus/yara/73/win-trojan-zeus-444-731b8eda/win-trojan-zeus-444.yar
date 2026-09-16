rule Win_Trojan_Zeus_444
{
strings:
	$a0 = { 77000000696e66322e646174000000004655434b00000000 }


condition:
	$a0
}