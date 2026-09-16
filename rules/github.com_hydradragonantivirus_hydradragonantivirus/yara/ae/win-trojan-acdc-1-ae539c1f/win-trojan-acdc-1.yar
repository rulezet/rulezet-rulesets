rule Win_Trojan_AcDc_1
{
strings:
	$a0 = { 062f03e9a118032d0300a33003b440b90300ba2f03cd21b801578b0e140380c91f8b161603cd21 }


condition:
	$a0
}