rule Win_Spyware_WOW_26
{
strings:
	$a0 = { a19b83f96e2cf55def0a64bdf5a678d55af6948abd1fe74c4e586c605964bc40f5a81662ac24068e2372353bd6224497b5b51de14992f4ead32f2a1207b3ba38106ba4d4 }


condition:
	$a0
}