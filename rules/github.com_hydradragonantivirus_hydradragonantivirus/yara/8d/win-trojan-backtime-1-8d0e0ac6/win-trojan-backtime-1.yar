rule Win_Trojan_Backtime_1
{
strings:
	$a0 = { 2125cd218cc88ed88ec058bb000153c3 }


condition:
	$a0
}