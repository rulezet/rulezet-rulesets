rule Win_Trojan_Mybot_5918
{
strings:
	$a0 = { 94fecf25b8d2968f57e632044a0bf2097c4faee7844e297ee08f5ec81ae827f382e94df115c290e6f172fcd470d34ccbc2d721f990abdf }


condition:
	$a0
}