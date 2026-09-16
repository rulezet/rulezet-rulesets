rule Win_Trojan_ABS_1
{
strings:
	$a0 = { 078ed033e48ed88ec01e33c0a381008ed81e8bf08bf8ff0e1304a11304b106d3e050508b1e4e }


condition:
	$a0
}