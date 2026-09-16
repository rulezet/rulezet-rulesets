rule Win_Trojan_SST_1
{
strings:
	$a0 = { eb01cd218a26ea01ebda9f208d858d80828886932095888c889e210a0d91a5e0a8ef20acaea8 }


condition:
	$a0
}