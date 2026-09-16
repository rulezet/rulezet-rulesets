rule Win_Trojan_CeCe_5
{
strings:
	$a0 = { 4797af1f8d5386508a430ec5a74636202c0d673b888fdcb64a7bc2cf930dc745dea8285039129d31 }


condition:
	$a0
}