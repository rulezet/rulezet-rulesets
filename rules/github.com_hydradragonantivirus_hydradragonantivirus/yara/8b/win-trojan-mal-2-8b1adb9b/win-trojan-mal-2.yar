rule Win_Trojan_Mal_2
{
strings:
	$a0 = { 02d1c0ba1602b44ecd21726ab29eb600b17a86e1b004d1e8cd2193b43fb90400ba2e02cd21bf2e02803d8b74 }


condition:
	$a0
}