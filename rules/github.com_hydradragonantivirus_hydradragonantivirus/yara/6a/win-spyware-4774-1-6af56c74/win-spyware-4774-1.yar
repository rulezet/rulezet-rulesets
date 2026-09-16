rule Win_Spyware_4774_1
{
strings:
	$a0 = { 565283c404c1cb05c1c30533 }


condition:
	$a0
}