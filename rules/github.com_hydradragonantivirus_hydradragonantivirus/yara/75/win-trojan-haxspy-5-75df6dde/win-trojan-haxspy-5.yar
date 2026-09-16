rule Win_Trojan_Haxspy_5
{
strings:
	$a0 = { 6874520010ff75f868a952001068153900106871870010e8b003000083c414e8c9feffffff45f0eba7 }


condition:
	$a0
}