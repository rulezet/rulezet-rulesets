rule Win_Trojan_Flashlight_1
{
strings:
	$a0 = { e800005d83ed03e9 }

	$a1 = { 60061eb8ddddcd213d11117503 }


condition:
	$a0 and $a1
}