rule Win_Trojan_Trivial_516
{
strings:
	$a0 = { 4b03045beb089009eb18504b0506ba3301b44ecd21ba9e00b8023dcd21938bd6b93900b440cd21b43ecd21b44fcd2173e4c32a2e632a00 }


condition:
	$a0
}