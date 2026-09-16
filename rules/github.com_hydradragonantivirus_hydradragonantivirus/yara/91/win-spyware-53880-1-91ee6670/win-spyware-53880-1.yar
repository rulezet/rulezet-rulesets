rule Win_Spyware_53880_1
{
strings:
	$a0 = { 08c745b47261792e897dbcc745c033363053c745c46166652e897dccffd683 }


condition:
	$a0
}