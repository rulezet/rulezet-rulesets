rule Win_Trojan_Intruder_3
{
strings:
	$a0 = { 8cc88ed88cc0a30400e867037518e86903e86903e826007509e88c03e8e401e8c903e8710358b80000fa8ed0bc8a06 }


condition:
	$a0
}