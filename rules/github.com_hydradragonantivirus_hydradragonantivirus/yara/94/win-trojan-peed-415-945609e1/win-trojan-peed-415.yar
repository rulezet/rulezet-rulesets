rule Win_Trojan_Peed_415
{
strings:
	$a0 = { 89c28d9417bd0c000081c22144000081fa21440000746c81 }


condition:
	$a0
}