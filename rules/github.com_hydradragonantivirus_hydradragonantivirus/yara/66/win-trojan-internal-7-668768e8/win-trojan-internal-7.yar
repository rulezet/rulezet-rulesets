rule Win_Trojan_Internal_7
{
strings:
	$a0 = { 6e616c2d2d3e[0-21]736176656e6f726d616c70726f6d70743d66616c7365 }

	$a1 = { 5c6166696c652e68746d }


condition:
	$a0 and $a1
}