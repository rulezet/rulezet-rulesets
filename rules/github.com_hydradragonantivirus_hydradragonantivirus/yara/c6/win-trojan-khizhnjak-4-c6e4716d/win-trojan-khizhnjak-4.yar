rule Win_Trojan_Khizhnjak_4
{
strings:
	$a0 = { 03b903008b1e5f03b440cd217204fe06f003833e5f03ff74218b0eed038b16eb03b80157 }


condition:
	$a0
}