rule Win_Trojan_WpcBats_1
{
strings:
	$a0 = { cf07b91800e813038b0ef3098b16f109b80042e8050333c9b440e8fe028b0eed098b16ef09 }


condition:
	$a0
}