rule Win_Trojan_Louse_1
{
strings:
	$a0 = { fe137d7c813b7a958f965b7fca3ecf66f5a9b381965e7f952aeeca41cf7dc4f57eb381dff27e7be4 }


condition:
	$a0
}