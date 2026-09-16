rule Win_Trojan_Anthrax_6
{
strings:
	$a0 = { b413cd2f0653b413cd2f585a87048754 }


condition:
	$a0
}