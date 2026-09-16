rule Win_Trojan_Fakeav_29
{
strings:
	$a0 = { b91900000083f91975188b0d40b23713baba000000890dc0c93713ba }

	$a1 = { 24151b424257074e21 }

	$a2 = { 6e776f6b5cf7777773f7 }


condition:
	$a0 and $a1 and $a2
}