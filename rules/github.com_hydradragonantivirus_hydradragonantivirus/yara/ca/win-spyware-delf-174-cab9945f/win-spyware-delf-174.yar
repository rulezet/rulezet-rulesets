rule Win_Spyware_Delf_174
{
strings:
	$a0 = { 5f5e5b59595dc300002d6e6f686f6d65006f70656e }


condition:
	$a0
}