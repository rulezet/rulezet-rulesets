rule Win_Trojan_Crypt_142
{
strings:
	$a0 = { 03fd[0-36]03c5[0-6]8b00[0-5]3107[0-4]83c704 }


condition:
	$a0
}