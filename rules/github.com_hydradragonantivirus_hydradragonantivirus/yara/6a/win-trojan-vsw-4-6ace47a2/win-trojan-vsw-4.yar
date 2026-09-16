rule Win_Trojan_VsW_4
{
strings:
	$a0 = { 9a0000cf005589e5b800069acd02cf0081ec0006bf58001e57bf5a001e57bf5c001e57bf5e001e579a0900b100833e5c }


condition:
	$a0
}