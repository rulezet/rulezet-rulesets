rule Win_Trojan_SillyC_10
{
strings:
	$a0 = { 50b4408bd683ea0bb90004cd215872442d0300538bde83eb0b2e894701c607e95bb8004233c9 }


condition:
	$a0
}