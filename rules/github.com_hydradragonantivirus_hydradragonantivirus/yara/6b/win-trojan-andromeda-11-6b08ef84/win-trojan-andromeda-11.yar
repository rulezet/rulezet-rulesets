rule Win_Trojan_Andromeda_11
{
strings:
	$a0 = { 7503e9e80080fc30750981fe34127503bfddfffb }


condition:
	$a0
}