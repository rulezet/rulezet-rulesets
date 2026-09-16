rule Win_Trojan_Hatev_1
{
strings:
	$a0 = { cd2180fc587504b44ccd21e800005e81ee13018a940b0380fa007410b9da018dbc31018a05 }


condition:
	$a0
}