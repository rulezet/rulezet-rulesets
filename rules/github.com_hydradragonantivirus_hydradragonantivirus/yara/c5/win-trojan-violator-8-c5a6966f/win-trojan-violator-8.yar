rule Win_Trojan_Violator_8
{
strings:
	$a0 = { fc8bf281c64c00b90300bf0001f3a48b }


condition:
	$a0
}