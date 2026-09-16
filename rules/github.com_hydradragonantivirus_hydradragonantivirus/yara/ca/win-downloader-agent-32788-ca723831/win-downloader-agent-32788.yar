rule Win_Downloader_Agent_32788
{
strings:
	$a0 = { 149d74c2e0f50bf15f34b43541b4feb3925ff7686b908e8eb6c49f9098afd2103ba4f4329a687e3bc2211da8bef64db16b5718dfc96ef4715cfde2f3ff7ee99e1d364c8f08cced88143693 }


condition:
	$a0
}