rule Win_Trojan_JD_4
{
strings:
	$a0 = { 53561e068bf2b42fcd21ac37740383c307061f8b471724 }


condition:
	$a0
}