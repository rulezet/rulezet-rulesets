rule Win_Trojan_No25_1
{
strings:
	$a0 = { fc30751083fb9a7403e9e502b002e8c104e9f40280fc11 }


condition:
	$a0
}