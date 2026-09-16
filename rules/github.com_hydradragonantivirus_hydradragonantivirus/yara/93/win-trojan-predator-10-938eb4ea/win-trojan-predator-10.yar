rule Win_Trojan_Predator_10
{
strings:
	$a0 = { bf18a3b88ad8b9bd04497808f7152ac14f4febf5 }


condition:
	$a0
}