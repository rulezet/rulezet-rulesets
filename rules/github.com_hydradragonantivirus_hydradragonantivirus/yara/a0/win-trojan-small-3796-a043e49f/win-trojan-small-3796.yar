rule Win_Trojan_Small_3796
{
strings:
	$a0 = { 1cd590620ae6d14c02d4a7a0c31492d6f7d3f1aa0d9e55a309600e71be5991c1d55f0671c25f98d7fe0c8ed27b49a7877a4ca39d09bda14cb2d41453aa2eebd9f9d87c4fe594f1aa7560d670ba2a }


condition:
	$a0
}