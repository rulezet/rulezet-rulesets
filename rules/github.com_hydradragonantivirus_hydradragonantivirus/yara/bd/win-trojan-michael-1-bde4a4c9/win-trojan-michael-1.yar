rule Win_Trojan_Michael_1
{
strings:
	$a0 = { 1e0633c08ed883ed088cc88ed88ec08bf581c639008bfeb94705fcac2e32860800aae2f7 }


condition:
	$a0
}