rule Win_Trojan_VGEN_788
{
strings:
	$a0 = { 89c423c0bbf1e4b991081e07311dfb81c3f5f683effee2f4901809ed30d04240592c25b15f9ea54d379ab20ead5086 }


condition:
	$a0
}