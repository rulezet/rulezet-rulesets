rule Win_Trojan_PCFlu_2G_1
{
strings:
	$a0 = { 2e282790904390909090e2 }


condition:
	$a0
}