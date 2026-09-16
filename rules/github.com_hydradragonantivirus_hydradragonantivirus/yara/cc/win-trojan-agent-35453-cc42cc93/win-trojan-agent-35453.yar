rule Win_Trojan_Agent_35453
{
strings:
	$a0 = { 6801604000e801000000c3c3b444bfabaeaf9741fb75dc47 }


condition:
	$a0
}