rule Win_Trojan_Small_177
{
strings:
	$a0 = { 566a200733ff89bc140160a761b94801f3a4560e066a1acb74118ed9be8400a5a5c744fcd3008c44fe1f1e075e5f }


condition:
	$a0
}