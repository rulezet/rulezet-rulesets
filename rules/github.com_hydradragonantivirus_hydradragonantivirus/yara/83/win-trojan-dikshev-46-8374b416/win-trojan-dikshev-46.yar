rule Win_Trojan_Dikshev_46
{
strings:
	$a0 = { 2a8bd6b44ecd21ba9e00b82e5bf2ae66c705434f4d008bcee80000cd2193b4408bd6 }


condition:
	$a0
}