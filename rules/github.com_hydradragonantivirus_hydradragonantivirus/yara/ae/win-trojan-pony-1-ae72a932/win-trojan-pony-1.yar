rule Win_Trojan_Pony_1
{
strings:
	$a0 = { 0300a31606b440ba00018b0eb505cd21b8004233d233c9cd21b440b90300ba1506cd21 }


condition:
	$a0
}