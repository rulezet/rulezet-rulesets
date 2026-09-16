rule Win_Trojan_Mini_54
{
strings:
	$a0 = { 3dba9e00cd2193b43f5459d1e2cd21387c3f741201d050b800429933c9cd2189f259b440cd21 }


condition:
	$a0
}