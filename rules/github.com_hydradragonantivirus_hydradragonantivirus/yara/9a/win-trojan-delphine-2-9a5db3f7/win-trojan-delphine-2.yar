rule Win_Trojan_Delphine_2
{
strings:
	$a0 = { cd20e800008bf48b2c81ed0800e8eb02ccfa33c0505b4c4c58fb3bc37402cd204444b8d0decd213dd0de74751e }


condition:
	$a0
}