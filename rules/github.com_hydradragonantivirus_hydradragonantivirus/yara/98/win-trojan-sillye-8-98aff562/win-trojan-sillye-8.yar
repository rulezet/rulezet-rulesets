rule Win_Trojan_SillyE_8
{
strings:
	$a0 = { 3f277a60e384235f9a04f1a7154da59bdaaf4d533c11f9b3c0ad69799826f3767bbd1dc387fa6998 }


condition:
	$a0
}