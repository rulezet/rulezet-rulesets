rule Win_Trojan_Albanian_1
{
strings:
	$a0 = { fb402f3bc3b903005053585b93e2f9e80000bb }


condition:
	$a0
}