rule Win_Trojan_Haxdoor_35
{
strings:
	$a0 = { 8bf08b45ec8bc84081f9e80300008945ec7c1668246d00106a02c745ec00000000e8212e000083c408 }


condition:
	$a0
}