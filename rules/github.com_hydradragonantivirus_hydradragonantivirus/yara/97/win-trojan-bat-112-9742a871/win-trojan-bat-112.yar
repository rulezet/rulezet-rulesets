rule Win_Trojan_BAT_112
{
strings:
	$a0 = { 6e65742073746f70202277736373766322 }


condition:
	$a0
}