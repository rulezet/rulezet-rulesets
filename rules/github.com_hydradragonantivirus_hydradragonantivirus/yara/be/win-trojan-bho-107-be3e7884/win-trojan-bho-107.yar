rule Win_Trojan_BHO_107
{
strings:
	$a0 = { 556852c4ca39500b8424b1ffffff6a002b }

	$a1 = { 374546377d203d20732027666c617368 }

	$a2 = { 2e446f776e4d67722e31 }


condition:
	$a0 and $a1 and $a2
}