rule Win_Trojan_Vandal_2
{
strings:
	$a0 = { 9d61e8f406609ceb1e9060e87206b949078cc88ed8ba0000b440e85506cdd0e8d70661c35e56 }


condition:
	$a0
}