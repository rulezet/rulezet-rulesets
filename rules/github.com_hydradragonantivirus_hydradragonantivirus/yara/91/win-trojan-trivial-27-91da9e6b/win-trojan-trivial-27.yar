rule Win_Trojan_Trivial_27
{
strings:
	$a0 = { ba9e00cd2193b43f5459d1e2cd21387c3f741203c250b800429933c9cd218bd659b440cd21 }


condition:
	$a0
}