rule Win_Trojan_Birgit_9
{
strings:
	$a0 = { b440b9e7038d960901cd215b53b801573e8b8e40033e8b964203cd215bb43ecd2168014358 }


condition:
	$a0
}