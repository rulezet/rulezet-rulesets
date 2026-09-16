rule Win_Trojan_Karas_1
{
strings:
	$a0 = { 408d960801b94c00cd21b935028db654018dbe9104f3a432e4cd1a8ae180f90074f580f9ff750d }


condition:
	$a0
}