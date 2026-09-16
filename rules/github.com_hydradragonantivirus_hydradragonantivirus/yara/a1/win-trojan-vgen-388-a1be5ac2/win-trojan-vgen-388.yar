rule Win_Trojan_VGEN_388
{
strings:
	$a0 = { fab430cd218b6efafc8d76f93c037c4f560633db8b57028edbb44a4bcd2180ee0533c0cd1291e363b426803ef104 }


condition:
	$a0
}