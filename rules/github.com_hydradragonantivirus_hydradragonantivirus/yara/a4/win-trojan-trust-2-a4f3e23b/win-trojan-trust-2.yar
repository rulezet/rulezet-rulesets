rule Win_Trojan_Trust_2
{
strings:
	$a0 = { 423d60ea773dfec42ea3ab0233c98bd1b80042cd21b90500b440baaa02cd21b8024233c9 }


condition:
	$a0
}