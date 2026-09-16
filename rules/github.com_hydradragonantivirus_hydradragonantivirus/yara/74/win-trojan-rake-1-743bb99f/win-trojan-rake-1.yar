rule Win_Trojan_Rake_1
{
strings:
	$a0 = { 01b9cf0390b4409c2eff1ec70432c0e85501ba8000b91a00b4409c2eff1ec704b801578b16d7 }


condition:
	$a0
}