rule Win_Trojan_Falsealert_1
{
strings:
	$a0 = { 558bec6aff680096470068d4e4430064a100000000506489 }

	$a1 = { 76697275732074686174 }

	$a2 = { 7a616d6f7769656e69652e657865 }


condition:
	$a0 and $a1 and $a2
}