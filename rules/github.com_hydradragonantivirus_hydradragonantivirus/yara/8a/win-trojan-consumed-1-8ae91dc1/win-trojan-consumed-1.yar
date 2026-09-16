rule Win_Trojan_Consumed_1
{
strings:
	$a0 = { 3e0f01007414be1b01b95e01eb01008a0432060f01880446e2f5b44e33c9babc01e88d00eb11b43ee88600b44fe881 }


condition:
	$a0
}