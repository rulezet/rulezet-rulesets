rule Win_Trojan_Psyme_36
{
strings:
	$a0 = { 6d656c617567682878297b }

	$a1 = { 646f63756d656e742e7772697465????????7d6d616b656d656c617567 }


condition:
	$a0 and $a1
}