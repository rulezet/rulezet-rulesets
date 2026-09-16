rule Win_Downloader_Swizzor_556
{
strings:
	$a0 = { d76357a359bab949ec2f04c21b0a5690bb0dec2b548e611ed266d96a230c0309e2259bf2a51456953ecbdbc589b51d5d0074331bb8f14096b05f13d028236e12bc376c7fdc4d332407b1fbbe }


condition:
	$a0
}