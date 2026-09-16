rule Win_Trojan_Vienna_114
{
strings:
	$a0 = { 1181c18b038bfe81ef8902890db440b9a6148bd681ea8b02e807fe72213da614751cb80042 }


condition:
	$a0
}