rule Win_Trojan_Monster_43
{
strings:
	$a0 = { 74facd8074fdcdeb00b0cdb966023130048be2fb }


condition:
	$a0
}