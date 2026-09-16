rule Win_Trojan_MKWorm_1
{
strings:
	$a0 = { 83e00f4091e81600e2fb59c35251b42ccd21e4408ae0e44033c133d0eb1b525153b80000ba0000b90700d1e0 }


condition:
	$a0
}