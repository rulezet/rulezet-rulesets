rule Win_Trojan_Hitohana_1
{
strings:
	$a0 = { aa0f590bc07400b8270050b8fc0250b8c30050e8231183c4068bf0eb2cb8c70050b81a0350e8a1 }


condition:
	$a0
}