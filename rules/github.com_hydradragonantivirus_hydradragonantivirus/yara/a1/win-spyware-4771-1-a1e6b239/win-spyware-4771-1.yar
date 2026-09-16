rule Win_Spyware_4771_1
{
strings:
	$a0 = { 53525a57535ff7d7575b5f }


condition:
	$a0
}