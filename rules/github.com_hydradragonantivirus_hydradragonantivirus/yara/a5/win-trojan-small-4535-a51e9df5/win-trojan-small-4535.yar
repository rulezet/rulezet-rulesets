rule Win_Trojan_Small_4535
{
strings:
	$a0 = { b826d7420096ad6a016a026a036a04ff }


condition:
	$a0
}