rule Win_Trojan_Vienna_31
{
strings:
	$a0 = { 0300894504b9ff0183fa00753d8bd72bf983c7020503019003c18905b4408bfa2bd1b91b02cd21 }


condition:
	$a0
}