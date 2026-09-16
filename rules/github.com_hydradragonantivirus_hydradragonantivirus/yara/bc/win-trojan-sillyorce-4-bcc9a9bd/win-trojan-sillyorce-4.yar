rule Win_Trojan_SillyORCE_4
{
strings:
	$a0 = { 03015152b440ba0001b9c8009c2eff1e0301b801575a599c2eff1e0301b43e9c2eff1e0301 }


condition:
	$a0
}