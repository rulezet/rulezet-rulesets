rule Win_Trojan_ExeHeader_7
{
strings:
	$a0 = { 33f68cdb4b8edbba80002954038b5c038cc003c38ec08a04268804c6044d26c7440108002954124a268954030e1fbe }


condition:
	$a0
}