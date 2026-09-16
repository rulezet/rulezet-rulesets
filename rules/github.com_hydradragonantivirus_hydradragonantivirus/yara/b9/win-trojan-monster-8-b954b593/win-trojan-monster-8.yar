rule Win_Trojan_Monster_8
{
strings:
	$a0 = { 33c98bd1cd21b440b90300ba1a0003d6cd21b8024233c98bd1cd21b440b910028bd6cd215a }


condition:
	$a0
}