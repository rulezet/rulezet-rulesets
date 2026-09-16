rule Win_Trojan_Massacre_3
{
strings:
	$a0 = { c79acd2f0e1f3dc89a7502eb6eb82135cd21899e0b048c860d04b82f35cd21899e31048c863304 }


condition:
	$a0
}