rule Win_Trojan_W_313
{
strings:
	$a0 = { 80f90f7502f3a4cf663d4e717560ccc8001000beb912f7bf66b8023dffd6724c }


condition:
	$a0
}