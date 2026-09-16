rule Win_Spyware_58987_1
{
strings:
	$a0 = { 558bec81ec3c0c0000568d85f4fcffff57 }

	$a1 = { 6d792e657865 }

	$a2 = { 54726f6a616e4d4858592e646c6c }


condition:
	$a0 and $a1 and $a2
}