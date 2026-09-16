rule Win_Trojan_Rukap_69
{
strings:
	$a0 = { 3f877e869de96770ac60c35e2b9313dd06a2ac48edde0172b183acd431b4bfb15e601d3ba57f7e9f98ab9929f1dba098908d7d482f66ca3a6e42a8068276f7d34c }


condition:
	$a0
}