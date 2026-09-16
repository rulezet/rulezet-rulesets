rule Win_Trojan_PS_48
{
strings:
	$a0 = { 10008036080028b440b9cc02bacc02cd21b8004233c999cd21b440ba9d0559cd21b801575a59cd }


condition:
	$a0
}