rule Win_Trojan_AntiFort_4
{
strings:
	$a0 = { b81325cd21cf1e060e1fb81335cd218bc38bdc368b5f042e8947062e8c47088d570ab425cd21b8aa55cd13071f5b }


condition:
	$a0
}