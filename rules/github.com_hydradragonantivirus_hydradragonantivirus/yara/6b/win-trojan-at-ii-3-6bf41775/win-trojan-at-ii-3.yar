rule Win_Trojan_AT_II_3
{
strings:
	$a0 = { 0680f44b753db8023dcdc572369333ffb58c8ed91e }


condition:
	$a0
}