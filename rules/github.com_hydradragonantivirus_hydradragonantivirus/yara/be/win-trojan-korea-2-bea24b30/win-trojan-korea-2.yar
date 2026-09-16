rule Win_Trojan_Korea_2
{
strings:
	$a0 = { 8ed88ed0bcf0fffbbb13048b0748 }


condition:
	$a0
}