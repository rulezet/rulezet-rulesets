rule Win_Trojan_BDFactory_1
{
strings:
	$a0 = { 90609cfce8890000006089e531d2648b52308b520c8b5214 }


condition:
	$a0
}