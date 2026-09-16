rule Win_Trojan_Agobot_3
{
strings:
	$a0 = { 558bec6aff688059410068fee7400064 }

	$a1 = { 73006b0075006e0073002e006500780065 }


condition:
	$a0 and $a1
}