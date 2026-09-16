rule Win_Trojan_DVCL_1
{
strings:
	$a0 = { 2ab44e8bd6cd21ba9e00b82e5bf2ae66c705434f4d008bcecd2193b44073e4c3 }


condition:
	$a0
}