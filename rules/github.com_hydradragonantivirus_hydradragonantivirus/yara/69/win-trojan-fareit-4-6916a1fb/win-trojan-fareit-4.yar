rule Win_Trojan_Fareit_4
{
strings:
	$a0 = { e800400000ba53c538664020cf535d8d4b525d0000acbd4b66cf5dd438baa220c7383eb3005300f6bd530053ccc6f6523ec562a24baca9a9ac006600202038c6 }


condition:
	$a0
}