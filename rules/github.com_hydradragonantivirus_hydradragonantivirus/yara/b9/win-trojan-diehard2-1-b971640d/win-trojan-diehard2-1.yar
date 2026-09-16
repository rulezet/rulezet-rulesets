rule Win_Trojan_DieHard2_1
{
strings:
	$a0 = { 5b0e07fdab8bc6b104d3e8408cca03c28bd080e40f80fc0e750b2cbf76073c4077039803d08bc22d4001ab8bcc }


condition:
	$a0
}