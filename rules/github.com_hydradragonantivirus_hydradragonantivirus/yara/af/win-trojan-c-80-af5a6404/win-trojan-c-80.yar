rule Win_Trojan_C_80
{
strings:
	$a0 = { 170b83c4048bf0badd10528d961aef5257e8a10283c4068946fa508d961aef5256e8100d83c406 }


condition:
	$a0
}