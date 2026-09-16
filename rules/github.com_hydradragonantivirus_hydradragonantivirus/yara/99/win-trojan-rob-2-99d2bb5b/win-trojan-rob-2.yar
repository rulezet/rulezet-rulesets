rule Win_Trojan_Rob_2
{
strings:
	$a0 = { cd213c017f02cd20b80935cd2189dfb0cfaa0e0e1f07be4501b96e03b2ffb300301a3012feca }


condition:
	$a0
}