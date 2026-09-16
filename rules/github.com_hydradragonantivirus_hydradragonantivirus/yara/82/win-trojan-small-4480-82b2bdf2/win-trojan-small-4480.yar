rule Win_Trojan_Small_4480
{
strings:
	$a0 = { 89e08b401c8d80????77045068623435 }


condition:
	$a0
}