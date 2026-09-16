rule Win_Trojan_Phoenix_6
{
strings:
	$a0 = { 6193ab58ab8bc18ae9b106d2ed8acc243f8bf15fb28033c932f65186cdd0c9d0c94150b403cd13 }


condition:
	$a0
}