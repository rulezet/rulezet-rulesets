rule Win_Trojan_N_59
{
strings:
	$a0 = { fa8ed3bc007c8ec4fbb9b628ba00002ae4cd13b80402cd1372f506b8220050cb }


condition:
	$a0
}