rule Win_Trojan_Deadman_3
{
strings:
	$a0 = { 1adbfb00000f87a400b440cd21b8004233c999cd21b440b9240290b601cd21e98b008b5414 }


condition:
	$a0
}