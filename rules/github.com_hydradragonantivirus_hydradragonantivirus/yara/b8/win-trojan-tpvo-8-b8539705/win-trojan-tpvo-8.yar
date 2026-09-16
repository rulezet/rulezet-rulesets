rule Win_Trojan_TPVO_8
{
strings:
	$a0 = { 5e81ee06000e1fb80083cd213d83457573b42acd2181fa0d04753381c6b90356565fb9c200 }


condition:
	$a0
}