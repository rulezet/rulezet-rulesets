rule Win_Trojan_ExeHeader_6
{
strings:
	$a0 = { 2e8c56002e8966020e178be550535156571e06fc33f68cdb8cd8488ed88b4c0383e922894c034003c18ed840c6 }


condition:
	$a0
}