rule Win_Trojan_Swiss_5
{
strings:
	$a0 = { 4f8bd5ebbcc646000045c746000d00 }


condition:
	$a0
}