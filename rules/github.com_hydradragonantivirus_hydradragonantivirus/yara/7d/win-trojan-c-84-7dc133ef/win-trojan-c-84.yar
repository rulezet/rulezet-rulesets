rule Win_Trojan_C_84
{
strings:
	$a0 = { 81ed0600508db61b008bfeb92a02ac342baae2fa05a0ad6a2905a0b5682905882b2a05a235292a9f01e60aab }


condition:
	$a0
}