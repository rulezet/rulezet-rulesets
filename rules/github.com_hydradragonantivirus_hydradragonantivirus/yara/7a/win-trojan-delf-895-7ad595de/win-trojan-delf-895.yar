rule Win_Trojan_Delf_895
{
strings:
	$a0 = { 68c0d40100e8f0f5ffffe8f3fdffff84c074edff159c6640006a008d45ccb9c04340008b1598664000e874efffff8b45cce8f0efffff50e8cef5ffffeb0c }


condition:
	$a0
}