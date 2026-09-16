rule Win_Trojan_Smiley_3
{
strings:
	$a0 = { e82400e83b008bf1cb07bb007c53b9030051 }


condition:
	$a0
}