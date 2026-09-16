rule Win_Trojan_VGEN_95
{
strings:
	$a0 = { 03437bea7951baa2028bf28b16460f8a13fceb4590cd138a12b40081e1f0048a147510b83f10b99d01f2ae8a13 }


condition:
	$a0
}