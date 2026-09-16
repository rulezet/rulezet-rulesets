rule Win_Trojan_TCP_2
{
strings:
	$a0 = { b8b1bacd213d03ba74578cd8488ed88b1e030083eb1eb44acd21b448bb1d }


condition:
	$a0
}