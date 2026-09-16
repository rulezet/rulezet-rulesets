rule Win_Trojan_Peed_409
{
strings:
	$a0 = { 89c28d9417a122000081ea1fb1ffff81fae14e00 }


condition:
	$a0
}