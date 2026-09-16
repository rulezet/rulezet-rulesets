rule Win_Trojan_Small_2065
{
strings:
	$a0 = { 5589e581ec9400000081ecfc0c000089e38925????4000a1??60 }


condition:
	$a0
}