rule Win_Trojan_Prodigy_1
{
strings:
	$a0 = { 0ec3018916c101ba0001b440b90c01cd2190b801578b16 }


condition:
	$a0
}