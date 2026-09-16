rule Win_Trojan_Lehigh_2
{
strings:
	$a0 = { fc8b44fe8ed8b84425cd21061f33 }


condition:
	$a0
}