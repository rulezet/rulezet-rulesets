rule Win_Trojan__1671_0008_000_1
{
strings:
	$a0 = { cd2193c3b43ecd21c3b43fcd21c3b440cd21c3b443cd21c3b456cd21c39c3dab63750433f69d }


condition:
	$a0
}