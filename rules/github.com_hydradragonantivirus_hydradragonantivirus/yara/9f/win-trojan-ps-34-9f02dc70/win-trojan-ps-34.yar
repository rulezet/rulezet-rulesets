rule Win_Trojan_PS_34
{
strings:
	$a0 = { fcb9dd00812c3432a7e2f91c33348fb51f45323a50ec6a64bd0c0055b32f6865a686be0c7bc20ab760373270c2 }


condition:
	$a0
}