rule Win_Trojan_VB_312
{
strings:
	$a0 = { 33db8d45b45368??18400050895ddc895dd8895dd4895dd0895dcc895dc8895dc4895db4ff1558104000 }


condition:
	$a0
}