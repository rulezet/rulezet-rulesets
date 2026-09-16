rule Win_Trojan_Autorun_406
{
strings:
	$a0 = { 6563686f205b6175746f72756e5d3e3e }

	$a1 = { 6175746f72756e2e696e66 }


condition:
	$a0 and $a1
}