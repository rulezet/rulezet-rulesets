rule Win_Dropper_Delf_827
{
strings:
	$a0 = { e89de6ffffb83c314000e837fbffff8bd8a174444000ba4c314000e822e8ffff75268bd3a178444000e8fcf7ffff }


condition:
	$a0
}