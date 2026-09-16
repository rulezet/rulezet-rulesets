rule Win_Trojan_TPVO_12
{
strings:
	$a0 = { e800005e81ee030056b8ff4bbb3261cd2181fb245b7446b44abbffffcd21b44a83eb3590cd21723533ff8cc8488ed803 }


condition:
	$a0
}