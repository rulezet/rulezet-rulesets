rule Win_Trojan_Creed_1
{
strings:
	$a0 = { 9d6281ef0b622e80851e00f04feb0075f5f810100a6e9be693fa2693d640161e2e1e2f430f6793d4169ce393fb13 }


condition:
	$a0
}