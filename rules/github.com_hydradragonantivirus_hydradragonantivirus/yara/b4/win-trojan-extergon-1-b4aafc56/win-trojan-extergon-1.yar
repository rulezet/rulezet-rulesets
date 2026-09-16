rule Win_Trojan_Extergon_1
{
strings:
	$a0 = { 881ab991b98a4779f8e3a75b8a7629c08e468c473e1833c882c8b98a4779952a2eecc395abe08a1a }


condition:
	$a0
}