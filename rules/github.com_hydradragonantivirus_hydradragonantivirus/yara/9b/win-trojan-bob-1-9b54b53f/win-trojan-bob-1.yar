rule Win_Trojan_Bob_1
{
strings:
	$a0 = { 0efe01268b1efc0183c101fa262b1e6c04261b0e6e04 }


condition:
	$a0
}