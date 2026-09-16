rule Win_Trojan_Vienna_106
{
strings:
	$a0 = { bf000156fcb90300f3a4b430cd213c027303e945015fc64506418b5d3b81c35005b104d3ebb44acd217303e92c }


condition:
	$a0
}