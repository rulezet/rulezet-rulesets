rule Win_Trojan_Abraxash_1
{
strings:
	$a0 = { b43d8d968403cd2193c3b801438d968403cd21c35b5db4408d960301b9ca01cd215355b003 }


condition:
	$a0
}