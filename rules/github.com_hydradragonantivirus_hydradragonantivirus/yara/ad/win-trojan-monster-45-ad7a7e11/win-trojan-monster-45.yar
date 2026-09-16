rule Win_Trojan_Monster_45
{
strings:
	$a0 = { 74facd8074fdcdeb00b0cdb977023130048be2fb }


condition:
	$a0
}