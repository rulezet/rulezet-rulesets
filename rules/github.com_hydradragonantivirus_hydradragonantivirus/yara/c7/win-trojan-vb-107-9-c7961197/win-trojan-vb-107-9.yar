rule Win_Trojan_VB_107_9
{
strings:
	$a0 = { dc6658f69db0469bfdff94b95599c9479a1ac7edde54bae6152c8897ffffff636c730d0a524f506c7567696e5f47656e65 }


condition:
	$a0
}