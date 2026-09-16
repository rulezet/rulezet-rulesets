rule Win_Trojan_Mtmp_1
{
strings:
	$a0 = { 8d96c803b440cd21b8024233c933d2cd21b9bb028d960001b440cd21b801578b8ee3038b96 }


condition:
	$a0
}