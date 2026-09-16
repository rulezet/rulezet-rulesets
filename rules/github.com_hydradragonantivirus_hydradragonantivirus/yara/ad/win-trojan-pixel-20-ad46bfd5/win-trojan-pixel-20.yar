rule Win_Trojan_Pixel_20
{
strings:
	$a0 = { 8201f3a4ba1801b41acd218c06140133ff8e062c0033c0b590f2aebe0b01b90500f3a67402ebf0 }


condition:
	$a0
}