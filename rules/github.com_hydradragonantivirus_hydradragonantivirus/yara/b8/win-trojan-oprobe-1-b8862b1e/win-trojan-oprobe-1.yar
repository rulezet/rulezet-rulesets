rule Win_Trojan_Oprobe_1
{
strings:
	$a0 = { 9500b80102b90100ba80008d9e1a1755bd4523cd135d2680be1a17907502eb77b80103b90e00cd }


condition:
	$a0
}