rule Win_Trojan_Trivial_504
{
strings:
	$a0 = { b90700ba3001cd21721cb8013dba9e00cd21720a93b440b136ba0001cd21b43ecd21b44febe0c35741534d5669722a2e434f4d00 }


condition:
	$a0
}