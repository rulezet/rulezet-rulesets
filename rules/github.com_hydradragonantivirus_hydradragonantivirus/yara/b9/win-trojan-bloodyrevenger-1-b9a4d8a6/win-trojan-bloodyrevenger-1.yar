rule Win_Trojan_BloodyRevenger_1
{
strings:
	$a0 = { 0290bb3b0103de8a840c014f0430300183ff0075f65bc3e8e3ffcd21e8deffc3 }


condition:
	$a0
}