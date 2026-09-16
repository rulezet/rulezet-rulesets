rule Win_Trojan_VB_22
{
strings:
	$a0 = { 6f6f204b6579204c6f6767657200000000a81d4000481d4000dc524000341e4000d01d4000e0524000cccccccccccccccccccccccce9e9e9e9cccccccccccccccccccccccc558bec83ec18687612400064 }


condition:
	$a0
}