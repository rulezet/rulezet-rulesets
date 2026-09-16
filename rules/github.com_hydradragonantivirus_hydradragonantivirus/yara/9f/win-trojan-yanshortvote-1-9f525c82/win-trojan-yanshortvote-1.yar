rule Win_Trojan_YanshortVote_1
{
strings:
	$a0 = { 8cd80e1fbedd0681ee030103f38904bedf0681ee030103f38cc089040e0753b8002fcd218bcb5bbe9c0a81ee030103f3890c83c6028cc089040e07bf03 }


condition:
	$a0
}