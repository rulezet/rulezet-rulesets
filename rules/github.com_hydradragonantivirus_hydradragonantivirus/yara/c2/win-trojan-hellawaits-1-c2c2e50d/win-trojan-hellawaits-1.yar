rule Win_Trojan_HellAwaits_1
{
strings:
	$a0 = { b90300ba3a00cd215a59b80157b6abcd21b43ecd21e8 }


condition:
	$a0
}