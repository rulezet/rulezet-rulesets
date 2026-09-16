rule Win_Trojan_Packed_51
{
strings:
	$a0 = { 50893c2453891424e8010100002ff773cd8b6348a073eb9fd74141a6b91f7077 }


condition:
	$a0
}