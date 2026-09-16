rule Win_Trojan_USSR_25
{
strings:
	$a0 = { 33c933d2e8a100b440b903008bd783c217e89400 }


condition:
	$a0
}