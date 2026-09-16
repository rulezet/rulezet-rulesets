rule Win_Trojan_NPox_2
{
strings:
	$a0 = { 99072e89169707e83c0274083d36f97203e9b200ba0301b9ba06b440e89d0272f0 }


condition:
	$a0
}