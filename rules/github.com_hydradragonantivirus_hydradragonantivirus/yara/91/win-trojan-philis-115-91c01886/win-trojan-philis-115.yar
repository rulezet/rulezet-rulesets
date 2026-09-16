rule Win_Trojan_Philis_115
{
strings:
	$a0 = { 565333f303de5b5e6057680fc100005f5fe8000000005333de5b52d3ca5a5ab8 }


condition:
	$a0
}