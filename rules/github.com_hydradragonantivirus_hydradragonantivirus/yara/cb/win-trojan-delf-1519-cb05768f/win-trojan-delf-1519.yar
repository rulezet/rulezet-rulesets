rule Win_Trojan_Delf_1519
{
strings:
	$a0 = { 33c05568d659400064ff30648920b8145a40008b0dcc864000ba485a4000e87c030000 }


condition:
	$a0
}