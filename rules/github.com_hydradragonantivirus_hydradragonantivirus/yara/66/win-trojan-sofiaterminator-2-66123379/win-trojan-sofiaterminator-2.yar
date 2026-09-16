rule Win_Trojan_SofiaTerminator_2
{
strings:
	$a0 = { ee032e89843d001e29c08ed8813e720433541f746a1e068cd8488ed8bf1200b8c0002945f12905ff35070e1f29ff }


condition:
	$a0
}