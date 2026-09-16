rule Win_Trojan_SillyC_89
{
strings:
	$a0 = { 03003e8986ab01b440b9c5008d960301cd21b8004233c933d2cd21b440b903008d96aa01cd21b4 }


condition:
	$a0
}