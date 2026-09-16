rule Win_Trojan_Austr_9
{
strings:
	$a0 = { 40b1d9cd21b800422bc92bd2cd21b440b103b601cd215a }


condition:
	$a0
}