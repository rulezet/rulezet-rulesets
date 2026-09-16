rule Win_Trojan_Sylvia_2
{
strings:
	$a0 = { 2e8a84ad022c142e8884ad02463c2475 }


condition:
	$a0
}