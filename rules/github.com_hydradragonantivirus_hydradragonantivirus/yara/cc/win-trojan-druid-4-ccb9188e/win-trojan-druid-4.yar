rule Win_Trojan_Druid_4
{
strings:
	$a0 = { ebfcba9e00b8023dcd21722793b80057cd215251b440b93d0190ba9e00cd21 }


condition:
	$a0
}