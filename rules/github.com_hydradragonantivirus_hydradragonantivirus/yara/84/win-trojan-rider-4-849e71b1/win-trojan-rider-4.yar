rule Win_Trojan_Rider_4
{
strings:
	$a0 = { 576a4f9a710986008dbe00ff1657bf9c021e579a57098600bf7d030e579ad60986006a3f }


condition:
	$a0
}