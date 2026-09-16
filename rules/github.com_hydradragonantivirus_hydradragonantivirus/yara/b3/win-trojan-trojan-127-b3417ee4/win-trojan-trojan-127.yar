rule Win_Trojan_Trojan_127
{
strings:
	$a0 = { 568b9ceb0481c65c01b98d0390d1e973014e8bfead }


condition:
	$a0
}