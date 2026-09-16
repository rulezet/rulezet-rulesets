rule Win_Trojan_Paix_1
{
strings:
	$a0 = { 17065d212121474f081e58004201bc001e010042031b81 }


condition:
	$a0
}