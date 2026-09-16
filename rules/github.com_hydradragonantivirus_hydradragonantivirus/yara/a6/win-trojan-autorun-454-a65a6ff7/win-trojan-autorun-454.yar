rule Win_Trojan_Autorun_454
{
strings:
	$a0 = { 7368656c6c657865637574653d6469736b3332646c6c2e657865 }


condition:
	$a0
}