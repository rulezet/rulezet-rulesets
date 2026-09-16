rule Win_Trojan_IRCBot_343
{
strings:
	$a0 = { 3a0abab0d18929d9d9786a4929d98996bef1526b6b6b6b9abff1546b6b6b6ba0ac1d5fb1026aabab9d9de596bf6f4aa16aabab4b8c36ab6f8a0b2aabab6b9ac00a8cba126f4ad62aabab4b8c38ab109a }


condition:
	$a0
}