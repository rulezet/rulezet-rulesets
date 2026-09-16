rule Win_Trojan_Warblade_1
{
strings:
	$a0 = { e800005e87f581ed0301e8fb03f7044130c1ce8a0fc7d0455b21aebd20324f81a8602f46c51dbe4797472ef327cab8a7 }


condition:
	$a0
}