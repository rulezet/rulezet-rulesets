rule Win_Trojan_Ornate_1
{
strings:
	$a0 = { 0200eb11bb567cb9d3008b07f7d089074343e2f6c3 }


condition:
	$a0
}