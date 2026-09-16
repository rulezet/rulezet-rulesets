rule Win_Trojan_Small_231_2
{
strings:
	$a0 = { 51689014c254687c20c254ff151020c25485c0a3c433c2547440 }


condition:
	$a0
}