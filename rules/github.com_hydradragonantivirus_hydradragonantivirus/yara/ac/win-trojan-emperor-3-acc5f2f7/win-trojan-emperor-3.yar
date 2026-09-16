rule Win_Trojan_Emperor_3
{
strings:
	$a0 = { 040000080000009e08000055a6450003000100200d00007b000000 }


condition:
	$a0
}