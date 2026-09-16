rule Win_Trojan_InvisibleEvil_1
{
strings:
	$a0 = { 0eb501b440b9120399cd217302722db80042b9000099cd21b440b90500bab401cd21 }


condition:
	$a0
}