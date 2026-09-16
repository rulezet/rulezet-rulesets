rule Win_Trojan_Infiltrator_1
{
strings:
	$a0 = { 8dbe0e018d8e07032bcf3e8b963f033035fec647e2f9 }


condition:
	$a0
}