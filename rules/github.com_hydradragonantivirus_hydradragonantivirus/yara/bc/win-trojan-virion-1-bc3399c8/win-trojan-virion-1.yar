rule Win_Trojan_Virion_1
{
strings:
	$a0 = { ff361800b440ba2b008b0eb042cd215a59b80157 }


condition:
	$a0
}