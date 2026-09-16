rule Win_Adware_WRU_1
{
strings:
	$a0 = { 41502e57525555 }

	$a1 = { 4b6c75637a }

	$a2 = { 43617074696f6e060457727521 }


condition:
	$a0 and $a1 and $a2
}