rule Win_Trojan_Vienna_129
{
strings:
	$a0 = { 51b89b03cd213d01017503e9????ba6d03fc8bf283c60a90b90300bf0001f3a4 }


condition:
	$a0
}