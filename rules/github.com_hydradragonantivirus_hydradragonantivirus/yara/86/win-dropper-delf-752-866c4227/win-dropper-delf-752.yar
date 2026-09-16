rule Win_Dropper_Delf_752
{
strings:
	$a0 = { 681c31141364ff30648920baa4561413b834311413e8e6feffff }


condition:
	$a0
}