rule Win_Adware_Winad_25
{
strings:
	$a0 = { 5c0355adf1aab12cebfb416a57562c33705e35976d3457 }

	$a1 = { 74703a2f2f7777772e313830736561726368617373697374616e }


condition:
	$a0 and $a1
}