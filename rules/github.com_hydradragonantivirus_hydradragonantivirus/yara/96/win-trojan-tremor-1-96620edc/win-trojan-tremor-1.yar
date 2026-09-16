rule Win_Trojan_Tremor_1
{
strings:
	$a0 = { ff2e9a002e8a04349c3c007405cd294675f2c3fae876f8b8 }


condition:
	$a0
}