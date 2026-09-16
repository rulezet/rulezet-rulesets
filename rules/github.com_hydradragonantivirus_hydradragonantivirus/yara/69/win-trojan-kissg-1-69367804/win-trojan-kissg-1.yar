rule Win_Trojan_KissG_1
{
strings:
	$a0 = { 997528b421cfb8024233c933d2cd21c39c2eff1ea903 }


condition:
	$a0
}