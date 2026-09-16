rule Win_Trojan_VGEN_134
{
strings:
	$a0 = { 069003437bea7951ba7f028bf28b16460f8b1bfceb4590cd138b1ab40081e1f0048b1c7510b81c10b99d01f2ae8b1b }


condition:
	$a0
}