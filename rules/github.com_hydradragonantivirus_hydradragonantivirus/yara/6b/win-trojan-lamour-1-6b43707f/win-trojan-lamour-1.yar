rule Win_Trojan_Lamour_1
{
strings:
	$a0 = { 092e81ac8e1440324e4e0f85f3ffd0c2d0bd2cbf08c1182dce02283d40bd96303beb4b3243f490f5f83440c53aba }


condition:
	$a0
}