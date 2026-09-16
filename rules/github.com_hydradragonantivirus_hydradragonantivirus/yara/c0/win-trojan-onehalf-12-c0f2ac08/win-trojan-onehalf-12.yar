rule Win_Trojan_OneHalf_12
{
strings:
	$a0 = { 7ac39bbe98f19ba35cf85bdb7c3982358f3511b1a5377fd3667e9a27827792477024a881c035551160cafc6606517af5 }


condition:
	$a0
}