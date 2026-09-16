rule Win_Trojan_Vienna_62
{
strings:
	$a0 = { b440b9a7028bd681ea0a02cd2172 }


condition:
	$a0
}