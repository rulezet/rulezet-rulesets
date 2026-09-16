rule Win_Trojan_Saddam_4
{
strings:
	$a0 = { bb00015350521e1eb800008ed8a11304 }


condition:
	$a0
}