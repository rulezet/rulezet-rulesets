rule Win_Trojan_Nostardamus_6
{
strings:
	$a0 = { 4c91a64b863e92fc64fd3829d989a6daae2ba3723e926ba431ff31973877f571cc7297fd8ff77197 }


condition:
	$a0
}