rule Win_Trojan_Trojan_279
{
strings:
	$a0 = { 722693b440ba0001b9cd02cd21b43ecd21b8004ccd210052616a616174202f2047656e65736973 }


condition:
	$a0
}