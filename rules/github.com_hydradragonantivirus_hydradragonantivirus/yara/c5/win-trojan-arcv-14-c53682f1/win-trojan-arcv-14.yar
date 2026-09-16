rule Win_Trojan_ARCV_14
{
strings:
	$a0 = { b157290df124102748a760d8a0b1f67e647d2d461827a25729be2d4614512d466bf6d41ce9ba6925 }


condition:
	$a0
}