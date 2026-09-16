rule Win_Trojan_SillyBP_1
{
strings:
	$a0 = { 2f01b95001f3a531dbb90100e88700fe0e0601ba000131c08ec0cd13b80102bb007cb90300cd13 }


condition:
	$a0
}