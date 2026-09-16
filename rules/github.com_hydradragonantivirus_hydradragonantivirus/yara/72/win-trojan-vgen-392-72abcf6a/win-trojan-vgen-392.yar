rule Win_Trojan_VGEN_392
{
strings:
	$a0 = { ed0300b430cd2181fb293b75110e8cdb33c08ed8ff368600688d008edbcb8cc0488ed833ff803d5976f4836d035b }


condition:
	$a0
}