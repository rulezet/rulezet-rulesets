rule Win_Trojan_Fakeav_14
{
strings:
	$a0 = { 33d0e9500300008bdb83c404884c3414e88efcffff8bdb83c4048a5434 }

	$a1 = { 0468536c6565 }

	$a2 = { 3130323030 }


condition:
	$a0 and $a1 and $a2
}