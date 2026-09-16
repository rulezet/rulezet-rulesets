rule Win_Trojan_Mal_1
{
strings:
	$a0 = { b81502d1c0ba1502b44ecd21726ab29eb600b17a86e1b004d1e8cd2193b43fb90400ba2d02cd21bf2d02803d8b74 }


condition:
	$a0
}