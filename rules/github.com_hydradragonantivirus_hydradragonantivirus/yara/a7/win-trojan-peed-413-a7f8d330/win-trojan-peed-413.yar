rule Win_Trojan_Peed_413
{
strings:
	$a0 = { 89c28d9417d508000081c22132000081fa213200 }


condition:
	$a0
}