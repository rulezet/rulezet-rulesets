rule Win_Trojan_SMan_1
{
strings:
	$a0 = { 80f44c2e882743e2f4b800908ec00e1fbe0001bf0001b9b901f3a406b8430150cbb82135cd21 }


condition:
	$a0
}