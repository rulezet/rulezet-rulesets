rule Win_Spyware_Delf_850
{
strings:
	$a0 = { b9185d4000e876c6ffff8b45fce81ac8ffff50e8eccdffff33c05a5959648910680d5d40008d45fce8afc4ffffc3e98dc0ffffebf0595dc3ffffffff0c00000073657276696365732e657865 }


condition:
	$a0
}