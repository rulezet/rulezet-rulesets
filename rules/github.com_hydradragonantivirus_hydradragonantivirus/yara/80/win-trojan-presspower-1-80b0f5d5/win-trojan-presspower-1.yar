rule Win_Trojan_PressPower_1
{
strings:
	$a0 = { e803ba0100bb00a08edb33dbcd265832e4b280cd13b80803ba8000b901001e0733dbcd1332 }


condition:
	$a0
}