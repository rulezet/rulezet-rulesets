rule Win_Trojan_Gen_94
{
strings:
	$a0 = { 6c043b066c0474fa581fc3061e0e1fb81c35cd21891e79038c067b03b425bac902cd211f07c31e }


condition:
	$a0
}