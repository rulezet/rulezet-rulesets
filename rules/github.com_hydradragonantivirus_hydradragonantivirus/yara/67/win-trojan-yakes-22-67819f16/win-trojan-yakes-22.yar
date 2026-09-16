rule Win_Trojan_Yakes_22
{
strings:
	$a0 = { 8b8d0cf3ffff68007f000051898514f3ffffc78518f3ffff0600000089b51cf3ffffc78520f3ffff74f04400 }


condition:
	$a0
}