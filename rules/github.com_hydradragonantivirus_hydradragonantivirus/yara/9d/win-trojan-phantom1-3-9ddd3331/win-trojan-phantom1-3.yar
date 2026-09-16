rule Win_Trojan_Phantom1_3
{
strings:
	$a0 = { e9057f0f8be880fb5d2b75b10aba0c0280f0877f0681ffae180ae8c7c38da8d1ce28c981c2a91d30edc6c45989db }


condition:
	$a0
}