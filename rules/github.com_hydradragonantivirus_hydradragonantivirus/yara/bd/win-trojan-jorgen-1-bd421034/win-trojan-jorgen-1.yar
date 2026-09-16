rule Win_Trojan_Jorgen_1
{
strings:
	$a0 = { fecd213d47427456e800005e83ee0c1e8cd8488ed833ff }


condition:
	$a0
}