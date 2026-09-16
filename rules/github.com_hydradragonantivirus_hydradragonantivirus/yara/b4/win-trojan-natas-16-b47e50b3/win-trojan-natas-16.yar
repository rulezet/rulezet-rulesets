rule Win_Trojan_Natas_16
{
strings:
	$a0 = { bf40008edf836dd306908b45d3b10ad3c88ec0b80a0233dbb90700ba8000cd1372030653cb }


condition:
	$a0
}