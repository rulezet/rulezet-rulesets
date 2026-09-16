rule Win_Trojan_Radyum_5
{
strings:
	$a0 = { 0801e80400eb2101228db633018bfeb9e400ad33861201abe2f8c351e8eaff59b440cd21e8e2 }


condition:
	$a0
}