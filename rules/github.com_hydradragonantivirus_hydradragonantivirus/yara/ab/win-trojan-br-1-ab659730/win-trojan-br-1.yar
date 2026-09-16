rule Win_Trojan_BR_1
{
strings:
	$a0 = { 7503b4fecf80fc4b7403e91602505351525657061e }


condition:
	$a0
}