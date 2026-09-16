rule Win_Trojan_Coconut_7
{
strings:
	$a0 = { 110900740fb997068db662028bfeacf6d0aae2fac3 }


condition:
	$a0
}