rule Win_Trojan_Arch_2
{
strings:
	$a0 = { c3b457cd21c38bfa8bf251ac32c402c1aae2f859c38bfa8bf251ac2ac132c4aae2f859c3 }


condition:
	$a0
}