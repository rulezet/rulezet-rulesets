rule Win_Trojan_VGEN_27
{
strings:
	$a0 = { 4a99b264c47f2a06b706cd2fe8c200b8ad0486fb47742e0e17eef3a48d70888ed987cfff318c098771fe569ccd01 }


condition:
	$a0
}