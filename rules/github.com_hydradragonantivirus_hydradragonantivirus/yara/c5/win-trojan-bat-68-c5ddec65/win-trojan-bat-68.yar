rule Win_Trojan_BAT_68
{
strings:
	$a0 = { 666f726d617420633a202f79202f71 }

	$a1 = { 7461736b6b696c6c202f66202f696d206c736173732e657865 }


condition:
	$a0 and $a1
}