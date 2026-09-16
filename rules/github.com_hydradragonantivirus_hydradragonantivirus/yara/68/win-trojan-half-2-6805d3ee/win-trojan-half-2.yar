rule Win_Trojan_Half_2
{
strings:
	$a0 = { 50bf50001e579a42001600833efc00007403e9ab00bf7c001e57bf6e001e579a9a042200bf }


condition:
	$a0
}