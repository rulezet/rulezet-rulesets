rule Win_Trojan_Mandra_9
{
strings:
	$a0 = { be670326a16c04890407be1000b440e822006626c7451500000000b440ba0202b91c00cd2158 }


condition:
	$a0
}