rule Win_Trojan_Bancos_879
{
strings:
	$a0 = { eaebafc0062becb0c4166becb1c826abecb2cc36ebecb3d046fbeb06126cfa8920c190100201dc76ebedb7e0862beeb8e4966beeb9e8a6ab24eebaecb6ebeebbf0 }


condition:
	$a0
}