rule Win_Trojan_Killjpg_1
{
strings:
	$a0 = { e800005d81ed0801b91a018db6230189f78ab62201ac30f0aae2faeb01 }


condition:
	$a0
}