rule Win_Trojan_Priority_2
{
strings:
	$a0 = { c74fa0d739ed7e018b3103973790ed5d28d3ea0c63c8fa87c52acc0752ec55d8abb15762aec55d8abb15762aec55d8abb15762aec55fffd7f1cc7c76eb8b7045 }


condition:
	$a0
}