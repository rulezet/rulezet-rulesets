rule Win_Trojan_Small_164
{
strings:
	$a0 = { 50593d004b755c561e50535152b8023dcdb3724993b43f }


condition:
	$a0
}