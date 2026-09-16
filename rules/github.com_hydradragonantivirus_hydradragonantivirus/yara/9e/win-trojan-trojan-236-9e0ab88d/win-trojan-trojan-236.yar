rule Win_Trojan_Trojan_236
{
strings:
	$a0 = { 02e83000b440b921018d960301cd21b801578b8e3c028b }


condition:
	$a0
}