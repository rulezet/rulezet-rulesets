rule Win_Trojan__1304_0006_002_1
{
strings:
	$a0 = { 1c00b440cd2126c745150000ba9a06b440cd21268b4d0d268b550fd0ce80c664d0c6b80157cd21 }


condition:
	$a0
}