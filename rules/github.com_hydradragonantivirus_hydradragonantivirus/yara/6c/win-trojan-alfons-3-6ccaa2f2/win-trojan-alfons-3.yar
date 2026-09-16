rule Win_Trojan_Alfons_3
{
strings:
	$a0 = { b436cc40c3fc1e06b452cd21268b57fe2e89161205 }


condition:
	$a0
}