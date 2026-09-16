rule Win_Trojan_Agent_31826
{
strings:
	$a0 = { 5053683f000f0053535368ec1240006802000080ff1508104000 }


condition:
	$a0
}