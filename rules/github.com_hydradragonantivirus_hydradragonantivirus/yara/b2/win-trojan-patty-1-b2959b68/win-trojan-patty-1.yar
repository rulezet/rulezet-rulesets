rule Win_Trojan_Patty_1
{
strings:
	$a0 = { 03008986a712b4408d96a612b90300cd21b802422bc9cd21b4408d960301b97911cd21 }


condition:
	$a0
}