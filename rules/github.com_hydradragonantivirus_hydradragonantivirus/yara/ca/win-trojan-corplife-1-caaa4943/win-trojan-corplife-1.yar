rule Win_Trojan_Corplife_1
{
strings:
	$a0 = { 0e3c02eb01ea2eff364e01b815ff508becf756002e8f064e012e8f064e01e8f700b80130cd21 }


condition:
	$a0
}