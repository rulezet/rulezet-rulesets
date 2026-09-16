rule Win_Trojan_Trojan_118
{
strings:
	$a0 = { ed0300909090bb210003ddb941012e8a17d0ca2e881743e2f5e9 }


condition:
	$a0
}