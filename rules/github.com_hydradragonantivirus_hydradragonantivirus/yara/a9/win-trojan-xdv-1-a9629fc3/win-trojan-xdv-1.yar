rule Win_Trojan_XDV_1
{
strings:
	$a0 = { 2103b440cd218b0e8e048b169004 }


condition:
	$a0
}