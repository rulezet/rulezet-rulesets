rule Win_Trojan_Poseidon_19
{
strings:
	$a0 = { 558bec83e4f881ec1c0700008b4d085333db56b8a60000005789442418895c24 }

	$a1 = { 53ff742414ff1534f24100eb0233c05f5e5b8be55dc21000cccccccccccccccc }


condition:
	$a0 and $a1
}