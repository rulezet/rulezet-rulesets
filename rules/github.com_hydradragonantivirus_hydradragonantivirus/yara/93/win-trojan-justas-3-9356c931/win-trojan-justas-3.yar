rule Win_Trojan_Justas_3
{
strings:
	$a0 = { ffe862a3fbff0000ffffffff1b0000004d61696c2053687469726c69747a20436f6e666967757261746f72 }


condition:
	$a0
}