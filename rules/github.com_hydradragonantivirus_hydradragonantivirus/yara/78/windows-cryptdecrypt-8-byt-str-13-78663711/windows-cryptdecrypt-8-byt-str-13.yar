rule Windows_CryptDecrypt__8_byt_STR_13_
{
strings:
	$a0 = { 43727970744465637279707400 }

condition:
	$a0
}