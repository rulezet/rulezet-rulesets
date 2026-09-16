rule Win_Trojan_Nail_1
{
strings:
	$a0 = { 13048b042d020050bb4000f7e38ec0bb0001be007c8a6c04b1068a5405b600b80202cd1306 }


condition:
	$a0
}