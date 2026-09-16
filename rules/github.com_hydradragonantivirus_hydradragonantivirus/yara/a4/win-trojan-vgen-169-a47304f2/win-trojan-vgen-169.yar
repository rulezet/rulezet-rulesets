rule Win_Trojan_VGEN_169
{
strings:
	$a0 = { 4108ba59020500003b060200731a2d2000fa8ed0fb2d19008ec050b9c30033ff57be4401fcf3a5cbb409ba3201cd21 }


condition:
	$a0
}