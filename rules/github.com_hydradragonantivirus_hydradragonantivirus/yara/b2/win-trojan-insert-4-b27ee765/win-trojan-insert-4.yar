rule Win_Trojan_Insert_4
{
strings:
	$a0 = { e8f200b80263cd213bc374368cd8488ed833ff803d }


condition:
	$a0
}