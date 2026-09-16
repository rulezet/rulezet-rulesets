rule Win_Spyware_WOW_29
{
strings:
	$a0 = { 60dc4fea10db469de8d34d98fbc2241f9b561b4f5149517d935fd3d0a2046fe5a0cc5ba3b85ac1f0f9088715b2092971591715fdda4f4fef2435baddd877dd6a9a446f75 }


condition:
	$a0
}