rule Win_Trojan_Small_4115
{
strings:
	$a0 = { bd0b449b558d9df52fa5aa8dbd7137a5 }


condition:
	$a0
}