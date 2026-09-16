rule Win_Trojan_NRLG_2
{
strings:
	$a0 = { 15ff05f7158135cdb1fe05812d19ecf715f715802dee80 }


condition:
	$a0
}