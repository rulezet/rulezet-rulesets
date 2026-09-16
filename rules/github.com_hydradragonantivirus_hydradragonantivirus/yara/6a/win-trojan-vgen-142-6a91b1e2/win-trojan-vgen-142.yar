rule Win_Trojan_VGEN_142
{
strings:
	$a0 = { 95010bc0752390be8b058b3ed70781c7f70757b90f00f3a4c39090bef7078b0ed707bf000157f3a4c3900e580510 }


condition:
	$a0
}