rule Win_Trojan_Delf_1600
{
strings:
	$a0 = { 75338d55b8b8d8894000e86cb8ffff8b45b8bae8894000e8b7abffff75178d55b433c0e833bbffff8b45b4bafc894000e89eabffff }


condition:
	$a0
}