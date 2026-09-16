rule Win_Trojan_Packed_140
{
strings:
	$a0 = { 68f1613e45e8f51e020009c0c60424f0e84faa0100d0c0660fa3d066895c240c6681fdcd4ce869ecffffe8ce8d0100aaf6d3887c24080f92c3f6d3b3028d64240c }


condition:
	$a0
}