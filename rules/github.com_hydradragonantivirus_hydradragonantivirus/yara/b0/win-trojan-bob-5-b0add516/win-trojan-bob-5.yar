rule Win_Trojan_Bob_5
{
strings:
	$a0 = { b43ecd21b8023dcd2172b48bfa81c76200ab93b440b90400ba0001cd21b4408bf781c6fcff8104 }


condition:
	$a0
}