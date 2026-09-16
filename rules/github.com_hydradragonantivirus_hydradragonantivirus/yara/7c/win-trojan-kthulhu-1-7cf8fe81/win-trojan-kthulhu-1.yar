rule Win_Trojan_Kthulhu_1
{
strings:
	$a0 = { 028bf2ba00fc8bfab91400f3a4bad10283c21a8bf2 }


condition:
	$a0
}