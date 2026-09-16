rule Win_Trojan_Crypt_139
{
strings:
	$a0 = { 5589e583ec1cff750cff253646733501c28951085f5ee9faecffffff35b44a7335ff152c4a733583c410ff251e497335508d85d8fdffff50ff2518487335 }


condition:
	$a0
}