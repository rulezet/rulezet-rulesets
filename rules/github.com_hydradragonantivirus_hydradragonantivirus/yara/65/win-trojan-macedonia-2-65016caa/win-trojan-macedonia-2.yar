rule Win_Trojan_Macedonia_2
{
strings:
	$a0 = { 33c08ec0bfe001b9e000a5e2fd061fa1 }


condition:
	$a0
}