rule Win_Trojan_Indonga_6
{
strings:
	$a0 = { 0c530ad134f32afc344506a2d717fd2ac92b3572e8f3ebf446b83d6a2d66e2d9ec69091f662cfc6a }


condition:
	$a0
}