rule Win_Trojan_Win_50
{
strings:
	$a0 = { 45068e05b8004233c98b16d70183ea08cd21b4408b0ed30183c108ba8403cd21ff368003ff3682 }


condition:
	$a0
}