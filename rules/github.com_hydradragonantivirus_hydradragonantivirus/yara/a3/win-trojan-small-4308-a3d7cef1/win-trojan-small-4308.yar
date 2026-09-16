rule Win_Trojan_Small_4308
{
strings:
	$a0 = { bb999bedfd81eb999badfd81e8891a25260589362726535e }


condition:
	$a0
}