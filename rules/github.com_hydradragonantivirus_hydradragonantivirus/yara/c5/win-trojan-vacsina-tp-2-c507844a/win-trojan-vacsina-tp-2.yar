rule Win_Trojan_Vacsina_TP_2
{
strings:
	$a0 = { 33ff06cd210732c081ffaa557502fec02e88875f00 }


condition:
	$a0
}