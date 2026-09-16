rule Win_Trojan_VGEN_347
{
strings:
	$a0 = { 25012e8c0627018cc88ed88ec0b44eb90000ba0401cd217303e92901be9e00bf0a012e8e1e2501b90c00fcf2a4 }


condition:
	$a0
}