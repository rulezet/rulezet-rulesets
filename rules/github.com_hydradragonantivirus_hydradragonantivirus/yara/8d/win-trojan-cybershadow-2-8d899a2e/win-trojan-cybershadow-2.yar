rule Win_Trojan_CyberShadow_2
{
strings:
	$a0 = { ff80c4d681e9c8a081c1c8a081e0ffff90525aeb000adbf585db84c4cc9080e2fffcf50bffe28f }


condition:
	$a0
}