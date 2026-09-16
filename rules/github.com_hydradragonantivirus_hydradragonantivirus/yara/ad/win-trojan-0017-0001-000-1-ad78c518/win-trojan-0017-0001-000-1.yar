rule Win_Trojan__0017_0001_000_1
{
strings:
	$a0 = { 21b8004233c999cd218bd6b90300b440cd218b4c198b541bb80157cd21b43ecd2132ed8a4c18 }


condition:
	$a0
}