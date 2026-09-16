rule Win_Trojan_Global_2
{
strings:
	$a0 = { badb010500003b060200731a2d2000fa8ed0fb2d19008ec050b9c40033ff57be4401fcf3a5 }


condition:
	$a0
}