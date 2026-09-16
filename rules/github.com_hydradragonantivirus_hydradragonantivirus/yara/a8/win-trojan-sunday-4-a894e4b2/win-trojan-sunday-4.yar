rule Win_Trojan_Sunday_4
{
strings:
	$a0 = { fcb4ffcd2180fcff731580fc047210b4 }


condition:
	$a0
}