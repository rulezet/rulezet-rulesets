rule Win_Spyware_Delf_871
{
strings:
	$a0 = { 8d85dffeffff50e86ce0ffffe8afffffff6a006a006a12a11c6140008b008b0050e8bae0ffff6a006a006a008d45e450e893e0ffff85c075ed8be55dc20400 }


condition:
	$a0
}