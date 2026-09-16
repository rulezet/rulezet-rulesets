rule Win_Trojan_Vandal_1
{
strings:
	$a0 = { 8cc88cdb3bc375279d61e81107609ceb1e9060e88f06b963078cc88ed8ba0000b440e87206cdd0e8f40661c35e56 }


condition:
	$a0
}