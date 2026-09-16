rule Win_Trojan_BVM_1
{
strings:
	$a0 = { c38b36010181c65001b9f0028a0432c2880446e2f7c3 }


condition:
	$a0
}