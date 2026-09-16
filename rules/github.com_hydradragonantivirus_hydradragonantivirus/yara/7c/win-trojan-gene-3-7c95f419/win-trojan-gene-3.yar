rule Win_Trojan_Gene_3
{
strings:
	$a0 = { ba9e00cd2193b80057cd215152b440b9c001ba0001cd21b801575a59cd21b43ecd21b44feb }


condition:
	$a0
}