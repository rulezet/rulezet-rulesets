rule Win_Trojan_Format1000_1
{
strings:
	$a0 = { 1005b90900ba8000bb0010cd13cd200d0a }


condition:
	$a0
}