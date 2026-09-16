rule Win_Trojan_November17_3
{
strings:
	$a0 = { cd217215b8004233c933d2cd21720ab440ba0503b90500cd218b0e18038b161603b80157cd21 }


condition:
	$a0
}