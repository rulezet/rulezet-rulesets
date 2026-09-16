rule Win_Trojan_Lowzones_7
{
strings:
	$a0 = { 6e64757064617465732e636f6d003a52616e676500003231332e3135392e3131 }


condition:
	$a0
}