rule Win_Trojan_Hidan_1
{
strings:
	$a0 = { ba02000000bb50274000bf7f204000e806070000ba01000000bb71274000bfb7 }


condition:
	$a0
}