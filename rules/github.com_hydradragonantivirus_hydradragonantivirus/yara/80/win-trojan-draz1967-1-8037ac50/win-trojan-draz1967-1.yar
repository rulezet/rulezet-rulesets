rule Win_Trojan_DRAZ1967_1
{
strings:
	$a0 = { b951008d96ee04cd21b440b931018d960001cd21b9c40651b440b901008d96c501cd2159e2f1 }


condition:
	$a0
}