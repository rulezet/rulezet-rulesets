rule Win_Trojan_VGEN_486
{
strings:
	$a0 = { 5f5a595b58e8bb0190e92bffb8024233c933d2cd21c350568bf2fcac22c074373c2e75f78b44f7 }


condition:
	$a0
}