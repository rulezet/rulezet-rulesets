rule Win_Trojan_Bancos_1745
{
strings:
	$a0 = { 3dad137668aedb0ac380bb5c75050396c8ddecf18a964d9c0eb3524f9cb4bfb398eeddcc9ebf38a32ce3908697ab16c5f3bcd17dd4fe25be1cd741fd79554e5304bd1d0323ae }


condition:
	$a0
}