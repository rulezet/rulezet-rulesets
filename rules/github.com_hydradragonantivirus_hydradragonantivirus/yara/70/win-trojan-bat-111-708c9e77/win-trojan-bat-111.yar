rule Win_Trojan_BAT_111
{
strings:
	$a0 = { 6e65742073746f70202273647273766322 }


condition:
	$a0
}