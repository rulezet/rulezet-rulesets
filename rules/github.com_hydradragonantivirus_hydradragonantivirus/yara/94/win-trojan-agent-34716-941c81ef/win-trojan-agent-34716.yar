rule Win_Trojan_Agent_34716
{
strings:
	$a0 = { 558bec81ecd005000083a5ecfdffff005356576a4933c059 }

	$a1 = { 7965616974736a75737467617262616765 }


condition:
	$a0 and $a1
}