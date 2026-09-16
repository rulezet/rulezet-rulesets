rule Win_Trojan_VGEN_450
{
strings:
	$a0 = { 02cd16b800dbcd210ac07403e9c500b813cdcd213dcd137503e9b80006b82135cd212e899e }


condition:
	$a0
}