rule Win_Trojan_Wilbur_3
{
strings:
	$a0 = { e8cffe83fe00741432e48a8605028bcef6f132c086e0 }


condition:
	$a0
}