rule Win_Trojan_Rosen_2
{
strings:
	$a0 = { b440cd21b43ecd210e1fb44fcd2173cd }


condition:
	$a0
}