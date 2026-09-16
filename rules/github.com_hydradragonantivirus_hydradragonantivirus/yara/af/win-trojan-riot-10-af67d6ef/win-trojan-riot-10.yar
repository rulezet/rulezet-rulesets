rule Win_Trojan_Riot_10
{
strings:
	$a0 = { 1fb8004233c999cd21b9f000b440ba0001cd219933c9b80157cd21b43ecd211f5a595b589dea }


condition:
	$a0
}