rule Win_Spyware_53859_1
{
strings:
	$a0 = { 45b47261792e895dbcc745c033363053c745c46166652e895dccffd683c41085 }


condition:
	$a0
}