rule Win_Trojan_Agent_35515
{
strings:
	$a0 = { c1ca0d330580464d00c1e80313d1391d801f4b007509 }


condition:
	$a0
}