rule Win_Trojan_DPVG_3
{
strings:
	$a0 = { 57e8aafdeb02eb138b46d2408946d28d7ed416579a3e004000ebd489ec5dc30844756b652f534d }


condition:
	$a0
}