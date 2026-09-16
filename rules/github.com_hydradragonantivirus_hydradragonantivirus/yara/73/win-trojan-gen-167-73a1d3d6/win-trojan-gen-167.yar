rule Win_Trojan_Gen_167
{
strings:
	$a0 = { 39015589e531c09a7c023901e871f1e823f7e810f8e870f6e880f8e8e7f8e828f9e808fae812fbe897fee8defe }


condition:
	$a0
}