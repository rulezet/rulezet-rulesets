rule Win_Trojan_Int_1
{
strings:
	$a0 = { 21e87c06b40980f440cd21b40880f440bbffffcd21b40880f44081eba900cd21b40880f440bba800cd217303b8 }


condition:
	$a0
}