rule Win_Trojan_Vgen_147
{
strings:
	$a0 = { 1eba5c020500003b060200731a2d2000fa8ed0fb2d25008ec050b9260133ff57be4401fcf3a5cbb409ba3201cd21 }


condition:
	$a0
}