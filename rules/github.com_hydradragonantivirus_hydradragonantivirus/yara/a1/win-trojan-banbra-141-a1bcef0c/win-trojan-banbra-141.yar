rule Win_Trojan_Banbra_141
{
strings:
	$a0 = { f34f2b4ed5b4624a7074ccd74ae1723eec5d4111620e4ae61065278f968e4f1ee85786c26788cbe9ea4f50c16cda144ecf6c09c69f768b2e65d190f6e4bc5be3ad824a4352d00d007a0eb8c025ff9d81 }


condition:
	$a0
}