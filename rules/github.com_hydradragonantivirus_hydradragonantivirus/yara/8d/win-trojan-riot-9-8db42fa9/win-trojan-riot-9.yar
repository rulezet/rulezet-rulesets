rule Win_Trojan_Riot_9
{
strings:
	$a0 = { b8004233c999cd21b9ef00b440ba0001cd219933c9b80157cd21b43ecd211f5a595b589dea }


condition:
	$a0
}