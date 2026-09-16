rule Win_Spyware_Banker_2104
{
strings:
	$a0 = { c34d6847e0d8067f1884fc80e9f836c4b3b5d24fa95fb35ac3ebafc37b84f3f3689d692b5d24a7f699f1ad74e5f5a49a7bc7ca61addc4a5fd04928138f205b90728e4762d65f8362ed50ab94ad79 }


condition:
	$a0
}