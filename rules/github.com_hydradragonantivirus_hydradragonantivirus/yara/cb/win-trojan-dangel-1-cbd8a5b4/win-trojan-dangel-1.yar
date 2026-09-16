rule Win_Trojan_Dangel_1
{
strings:
	$a0 = { ff8edf8ed7be007c8be6bb4c00c407898479018c847b013d19017419a113044848a31304b90602d3e08ec0fcf3a4c7 }


condition:
	$a0
}