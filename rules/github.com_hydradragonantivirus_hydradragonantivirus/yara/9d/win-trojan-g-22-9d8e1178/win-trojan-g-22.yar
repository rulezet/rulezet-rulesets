rule Win_Trojan_G_22
{
strings:
	$a0 = { 0e1f0e07bebe03bfbe01f3a4fec12bdbb80103cd13ebae0d0a547574746f }


condition:
	$a0
}