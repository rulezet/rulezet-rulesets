rule Win_Trojan_Dune_2
{
strings:
	$a0 = { e800005d83ed0381fd00017415eb029000bf2200b9210203fdb0 }


condition:
	$a0
}