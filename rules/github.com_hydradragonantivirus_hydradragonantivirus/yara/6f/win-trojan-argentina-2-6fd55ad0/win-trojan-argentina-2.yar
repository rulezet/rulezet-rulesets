rule Win_Trojan_Argentina_2
{
strings:
	$a0 = { 1e7105bae103b8003dcd2172338bd8 }


condition:
	$a0
}