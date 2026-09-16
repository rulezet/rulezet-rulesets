rule Win_Trojan_Aztech_1
{
strings:
	$a0 = { 30cd213c0372eba176043d0f00720bb42ccd210af67503e99003b800f08b167604cd2f4174cc0a }


condition:
	$a0
}