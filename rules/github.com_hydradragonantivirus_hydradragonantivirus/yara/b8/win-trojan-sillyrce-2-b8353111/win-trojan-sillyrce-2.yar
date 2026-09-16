rule Win_Trojan_SillyRCE_2
{
strings:
	$a0 = { 58484848abc60519b440b90a0190ba0002cd21b800429933c9cd2159b440ba0e03cd215058 }


condition:
	$a0
}