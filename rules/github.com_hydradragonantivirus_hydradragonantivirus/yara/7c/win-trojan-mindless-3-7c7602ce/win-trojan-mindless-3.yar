rule Win_Trojan_Mindless_3
{
strings:
	$a0 = { e90000b8eb02ebfcb805feebfc80c43bb9eb09b805feebfc80c43bebf40e1fbab002b80125cd21b003cd211e2bc050b42acd213c007557eb0190b9460090be2002bf66 }


condition:
	$a0
}