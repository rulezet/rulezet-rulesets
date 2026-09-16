rule Win_Trojan_Blakan_1
{
strings:
	$a0 = { 20627920 }

	$a1 = { 67656e657261 }

	$a2 = { 74696f6e20766972757320 }

	$a3 = { 4475206861737420646965204265726765 }


condition:
	$a0 and $a1 and $a2 and $a3
}