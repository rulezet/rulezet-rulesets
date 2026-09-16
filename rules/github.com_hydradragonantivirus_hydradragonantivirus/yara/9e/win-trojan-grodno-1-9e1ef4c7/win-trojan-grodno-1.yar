rule Win_Trojan_Grodno_1
{
strings:
	$a0 = { 42b000cd215aba740203d5b440b90300cd2133c933d2b442b002cd21ba000103d5b440b98f01 }


condition:
	$a0
}