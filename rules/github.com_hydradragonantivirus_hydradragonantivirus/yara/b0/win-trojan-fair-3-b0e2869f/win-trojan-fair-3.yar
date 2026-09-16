rule Win_Trojan_Fair_3
{
strings:
	$a0 = { 742beb0990902e803e220800c3e80400eb1b90902e8f06ea07fa2e8c1613082e892615088cc88ed0bcea07fbc3 }


condition:
	$a0
}