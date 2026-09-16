rule Win_Trojan_SillyOC_23
{
strings:
	$a0 = { 08ba0001b440b9a807cd21b801578b0ea4088b16a208cd21b43ecd21ba9e008b0ea608b801 }


condition:
	$a0
}