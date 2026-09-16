rule Win_Trojan_ZV_1
{
strings:
	$a0 = { f55eb499cd2180fc21750458eb5190 }


condition:
	$a0
}