rule Win_Trojan_Fungus_1
{
strings:
	$a0 = { 3e00005a740a40030603003d00a072ed8ed88bd8a10300 }


condition:
	$a0
}