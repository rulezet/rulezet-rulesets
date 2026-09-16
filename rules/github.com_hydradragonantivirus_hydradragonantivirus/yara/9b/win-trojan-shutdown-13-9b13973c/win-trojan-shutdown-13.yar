rule Win_Trojan_Shutdown_13
{
strings:
	$a0 = { 73687574646f776e202d73202d66202d74203020 }


condition:
	$a0
}