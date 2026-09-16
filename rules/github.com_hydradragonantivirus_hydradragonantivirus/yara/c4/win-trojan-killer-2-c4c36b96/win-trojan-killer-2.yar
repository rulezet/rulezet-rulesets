rule Win_Trojan_Killer_2
{
strings:
	$a0 = { 3db002ba9e00cd218bd8b4 }


condition:
	$a0
}