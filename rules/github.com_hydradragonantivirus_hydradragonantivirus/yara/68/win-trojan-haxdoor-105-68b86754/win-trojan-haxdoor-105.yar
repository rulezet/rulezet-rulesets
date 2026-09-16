rule Win_Trojan_Haxdoor_105
{
strings:
	$a0 = { 7970616c2e63c9911f324c652d676f6c64a2b67e32443bf275a4cd917803f7c358 }


condition:
	$a0
}