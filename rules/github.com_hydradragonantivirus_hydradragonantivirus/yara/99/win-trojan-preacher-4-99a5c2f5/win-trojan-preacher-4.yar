rule Win_Trojan_Preacher_4
{
strings:
	$a0 = { b44a0e07cd21b43cb90200ba0b01cd218bd87304b001eb6cb4402e8b0e0a03ba2503cd21b43ecd218cc82ea300 }


condition:
	$a0
}