rule Win_Trojan_LunchTime_1
{
strings:
	$a0 = { 1e06b8ffffcd213daaaa7503eb7990bbfe10b104d3eb43b80048cd217329bbfe10b104d3eb438cd88ec026a1020090 }


condition:
	$a0
}