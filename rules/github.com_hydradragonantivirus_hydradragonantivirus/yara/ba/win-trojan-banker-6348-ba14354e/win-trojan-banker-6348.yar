rule Win_Trojan_Banker_6348
{
strings:
	$a0 = { 558bec83c4f0b8e05b4700e828fff8ffa1947a47008b00e80013feff8b0d207c }


condition:
	$a0
}