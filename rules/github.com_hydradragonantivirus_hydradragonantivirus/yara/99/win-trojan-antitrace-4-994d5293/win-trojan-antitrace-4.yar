rule Win_Trojan_AntiTrace_4
{
strings:
	$a0 = { c7460200015d5053515256571e06e800005b81eb15009c5880cc01500eb9aa0003cb51e80e012ec7873601dd }


condition:
	$a0
}