rule Win_Trojan_VGEN_561
{
strings:
	$a0 = { 89862a038db60e028dbe870ab97908e8af06b4408bd7cd21b800422bc92bd2cd21b440b90400 }


condition:
	$a0
}