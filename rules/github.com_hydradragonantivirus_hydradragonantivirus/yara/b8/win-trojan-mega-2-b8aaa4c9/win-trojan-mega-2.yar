rule Win_Trojan_Mega_2
{
strings:
	$a0 = { 1e9405bcc8078cc88ed0e82604b4bbcd21fa80fcff7503e9ab00b449cd21 }


condition:
	$a0
}