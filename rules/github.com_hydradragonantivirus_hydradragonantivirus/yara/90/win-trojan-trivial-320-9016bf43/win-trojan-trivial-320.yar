rule Win_Trojan_Trivial_320
{
strings:
	$a0 = { b44eba3501e90000cd21b8cb00b8023dbacd00ba9e0081f1a50081f1a500cd21b7409383f24383f243ba0201b157b137cd21c3 }


condition:
	$a0
}