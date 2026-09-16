rule Win_Trojan_Cancenbero_1
{
strings:
	$a0 = { 81ed03001e060e0e071f3e80be27000074248db63b008bfeb90d073e8a962700eb0100ac32c2d0c8f6d0c0c005aa }


condition:
	$a0
}