rule Win_Trojan_Anarchy_7
{
strings:
	$a0 = { 5e5b5807c3b43eeb02b43f9c2eff1efd04c33dcdab7507b8fffff8ca02003dc00c750386c4 }


condition:
	$a0
}