rule Win_Trojan_VB_998
{
strings:
	$a0 = { 680c124000e8eeffffff0000000000003000000040 }

	$a1 = { 3a44d96d79 }

	$a2 = { 40004300680061006e006e0065006c }


condition:
	$a0 and $a1 and $a2
}