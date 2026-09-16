rule Win_Trojan_VGEN_537
{
strings:
	$a0 = { ebf52d3d5b56434c2f4245765d3d2d5ab41acd218be5c3558bec83ec40b44732d28d76c0cd21 }


condition:
	$a0
}