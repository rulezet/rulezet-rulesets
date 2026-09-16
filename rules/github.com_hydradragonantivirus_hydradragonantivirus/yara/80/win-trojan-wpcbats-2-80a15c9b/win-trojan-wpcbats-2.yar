rule Win_Trojan_WpcBats_2
{
strings:
	$a0 = { 08be050af3a4b9e708e80800ba0001b440e83200fd501e0633c08ed88cc88ec0bfd407893e06 }


condition:
	$a0
}