rule Win_Trojan_AvatarK_1
{
strings:
	$a0 = { 8cd315337572f9d4ff8ac4b40bbb0dd0cd210bdb74661e8cd8488ed82bff803d5a7559836d0327836d12278e4512e800005e81ee3200b91901f32ea58ed980 }


condition:
	$a0
}