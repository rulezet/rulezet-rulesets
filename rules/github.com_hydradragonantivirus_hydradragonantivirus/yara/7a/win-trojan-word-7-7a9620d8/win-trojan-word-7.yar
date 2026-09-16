rule Win_Trojan_Word_7
{
strings:
	$a0 = { 0200cd21bb11018037e14381fb700672 }


condition:
	$a0
}