rule Win_Trojan_V800_1
{
strings:
	$a0 = { 2e8e1621042eb8262304fb2e833ecf03 }


condition:
	$a0
}