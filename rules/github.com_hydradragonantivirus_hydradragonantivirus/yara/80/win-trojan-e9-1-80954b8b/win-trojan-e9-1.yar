rule Win_Trojan_E9_1
{
strings:
	$a0 = { 807d0ff8742e8ed9be007cfa8ed18be6fbff0e1304cd12b502c1e0068ec0f3a48ec1be4c00 }


condition:
	$a0
}