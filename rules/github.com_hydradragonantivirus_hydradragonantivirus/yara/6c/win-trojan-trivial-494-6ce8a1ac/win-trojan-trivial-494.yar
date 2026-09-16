rule Win_Trojan_Trivial_494
{
strings:
	$a0 = { ba2301cd217227b8023dba9e00cd21b740ba0001938acccd21b43ecd21b44febdf2a2e636f6d0054726964656e74b42ccd2180fa0a7706b00233d2cd25c3 }


condition:
	$a0
}