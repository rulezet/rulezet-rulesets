rule Win_Trojan_Feci_1
{
strings:
	$a0 = { 733297c94ec337eb03ff2f04b9458bff7756fecd265a817efee80375eae3f809b0025b87e4f80e }


condition:
	$a0
}