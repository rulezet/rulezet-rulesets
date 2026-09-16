rule Win_Trojan_Doubleheart_2
{
strings:
	$a0 = { c706e70193192bc92bd28b1ef301b80042cd21720ebad501b918008b1ef301b440cd218b1e }


condition:
	$a0
}