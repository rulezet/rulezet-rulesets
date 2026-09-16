rule Win_Trojan_SillyC_144
{
strings:
	$a0 = { 3fe95b744eb8024233c933d2cd21725650b4408bd681ea0b00b90401cd2158724583e803538bde }


condition:
	$a0
}