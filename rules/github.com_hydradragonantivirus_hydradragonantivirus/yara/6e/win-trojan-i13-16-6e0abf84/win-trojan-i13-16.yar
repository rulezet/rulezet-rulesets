rule Win_Trojan_I13_16
{
strings:
	$a0 = { 02b440b96f01cd21e862ffb440ba6b03b90400cd21b4 }


condition:
	$a0
}