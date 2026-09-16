rule Win_Trojan_MiniMad_1
{
strings:
	$a0 = { 86610b2e8b865d0b502ec7865d0b0000b440ba4c0a03d5b91701903e8b9e5f0bcd21582e8986 }


condition:
	$a0
}