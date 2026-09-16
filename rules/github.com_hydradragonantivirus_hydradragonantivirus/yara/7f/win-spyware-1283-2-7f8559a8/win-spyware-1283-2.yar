rule Win_Spyware_1283_2
{
strings:
	$a0 = { 6e64212065786974696e672e2e2e006d616769632063697479 }


condition:
	$a0
}