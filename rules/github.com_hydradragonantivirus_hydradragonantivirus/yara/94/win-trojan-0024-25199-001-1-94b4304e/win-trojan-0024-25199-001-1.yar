rule Win_Trojan__0024_25199_001_1
{
strings:
	$a0 = { cd2133c9b8004299cd21b440ba890459cd21b801575a59cd21b43ecd21585a1f59cd215a1fb8 }


condition:
	$a0
}