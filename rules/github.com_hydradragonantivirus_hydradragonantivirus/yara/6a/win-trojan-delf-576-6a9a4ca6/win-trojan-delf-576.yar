rule Win_Trojan_Delf_576
{
strings:
	$a0 = { 8b45fcba24c20110e84d87feff75788d8580fdffffe864b9ffff8d8580fdffff8b5710e8f685feff8b8580fdffffbaa4c10110e82ea0ffffa1800f021050e88396feff6a00 }


condition:
	$a0
}