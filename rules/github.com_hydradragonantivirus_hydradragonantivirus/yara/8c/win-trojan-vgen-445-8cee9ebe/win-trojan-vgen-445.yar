rule Win_Trojan_VGEN_445
{
strings:
	$a0 = { b41acd21b8013580ec10bb00008ec3cd21b003cd21b42ccd2180fa0d7f04b082e621b42ccd2180 }


condition:
	$a0
}