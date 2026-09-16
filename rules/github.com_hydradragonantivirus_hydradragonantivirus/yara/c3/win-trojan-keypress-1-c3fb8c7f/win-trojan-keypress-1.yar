rule Win_Trojan_KeyPress_1
{
strings:
	$a0 = { 51521e069c0633c08ed8a184003d1e027447a184002ea31001a186002ea3120107068cc0488ed8bb3821b104d3eb }


condition:
	$a0
}