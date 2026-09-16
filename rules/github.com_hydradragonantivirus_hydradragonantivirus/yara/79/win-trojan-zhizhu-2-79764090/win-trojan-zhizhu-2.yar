rule Win_Trojan_Zhizhu_2
{
strings:
	$a0 = { 8bff558bece8bdffffff5de9d0feffff5c0044006f00730044006500760069006300650073005c00660073007400 }


condition:
	$a0
}