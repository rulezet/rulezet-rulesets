rule Win_Trojan_Monster_46
{
strings:
	$a0 = { 74facd8074fdcdeb00b0cdb97b023130048be2fb }


condition:
	$a0
}