rule Win_Trojan_Druid_2
{
strings:
	$a0 = { 02ebfcba9e00b8023dcd21722693b80057cd215251b440b9f800ba9e00cd21595ab80157cd21 }


condition:
	$a0
}