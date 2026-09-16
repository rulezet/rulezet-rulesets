rule Win_Trojan_Trivial_529
{
strings:
	$a0 = { b44ecd21ba????b8013dcd2193[0-5]b92400b126ba0001cd21cd21c3 }


condition:
	$a0
}