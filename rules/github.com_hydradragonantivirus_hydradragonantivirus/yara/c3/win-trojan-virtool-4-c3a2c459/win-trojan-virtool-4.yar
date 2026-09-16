rule Win_Trojan_Virtool_4
{
strings:
	$a0 = { 2d2d3d5148413d2d2d }

	$a1 = { 7077646c697374[0-14]433a5c706173732e747874 }

	$a2 = { 7369746561646472[0-14]6674702e786f6f6d2e636f6d }


condition:
	$a0 and $a1 and $a2
}