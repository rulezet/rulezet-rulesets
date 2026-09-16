rule Win_Trojan_Monster_47
{
strings:
	$a0 = { 74facd8074fdcdeb00b0cdb97c023130048be2fb }


condition:
	$a0
}