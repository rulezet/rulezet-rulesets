rule Win_Trojan_LittleRed_1
{
strings:
	$a0 = { 4b741d80fc30740f80fc117503e907ff80fc1274f8eb }


condition:
	$a0
}