rule Win_Trojan_Julius_1
{
strings:
	$a0 = { fe03be5606acaa0ac075fa5fe8e50b8bd7b441cd21720db44fcd2173e0075f5e5dca02003d05007503e9d02ae9 }


condition:
	$a0
}