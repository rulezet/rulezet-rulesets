rule Win_Trojan_SE_1
{
strings:
	$a0 = { ed0801b8cdabcd2181fabadc7403e86b00b42acd2181fa0302752db42bfec2cd21060e588ed88ec0b4098d969c04 }


condition:
	$a0
}