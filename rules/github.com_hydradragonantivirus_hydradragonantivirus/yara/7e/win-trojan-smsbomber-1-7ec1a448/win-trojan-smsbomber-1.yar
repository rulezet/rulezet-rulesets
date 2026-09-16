rule Win_Trojan_SMSBomber_1
{
strings:
	$a0 = { 3803f517feff872d35770d010a00534d532d426f6d6265720019dbaed9fe13220126202d4a0d481203506e }


condition:
	$a0
}