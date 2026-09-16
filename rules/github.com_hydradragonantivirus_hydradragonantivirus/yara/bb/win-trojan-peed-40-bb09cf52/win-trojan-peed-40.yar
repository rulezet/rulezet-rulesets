rule Win_Trojan_Peed_40
{
strings:
	$a0 = { 89c381c32c4f40006a4281c3ff23511f }


condition:
	$a0
}