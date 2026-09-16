rule Win_Trojan_Yankee_6
{
strings:
	$a0 = { 5d084781ef030103fbba000053e875 }


condition:
	$a0
}