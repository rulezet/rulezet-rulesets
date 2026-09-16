rule Win_Trojan_Tamsui_1
{
strings:
	$a0 = { 2125cd21b42a9cff1ee20580fe0c753180fa17762c80fa }


condition:
	$a0
}