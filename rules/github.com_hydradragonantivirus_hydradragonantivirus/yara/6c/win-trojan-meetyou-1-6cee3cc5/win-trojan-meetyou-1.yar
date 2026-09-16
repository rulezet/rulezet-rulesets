rule Win_Trojan_MeetYou_1
{
strings:
	$a0 = { b44ecd21721eba9e00b8013dcd21518bd8b440b91501ba0001cd2159b44fcd217202e2e2c3 }


condition:
	$a0
}