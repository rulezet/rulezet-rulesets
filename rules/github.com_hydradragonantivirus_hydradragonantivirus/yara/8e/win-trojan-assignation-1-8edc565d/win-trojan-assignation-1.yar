rule Win_Trojan_Assignation_1
{
strings:
	$a0 = { b844414c56cd21663d4b434f5274d58cd8488ed86633ff }


condition:
	$a0
}