rule Win_Trojan_Autorun_377
{
strings:
	$a0 = { 6f70656e3d726573746f72655c }

	$a1 = { 2e657865 }


condition:
	$a0 and $a1
}