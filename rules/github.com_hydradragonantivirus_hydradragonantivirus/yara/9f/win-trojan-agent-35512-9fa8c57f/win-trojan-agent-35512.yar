rule Win_Trojan_Agent_35512
{
strings:
	$a0 = { 5589e583ec468b353e13410083f8067c0601de }


condition:
	$a0
}