rule Win_Trojan_Enumiacs_1
{
strings:
	$a0 = { fe205b456e756d65726f5d206279205669726f67656e205b4e4f505d20fe0000 }


condition:
	$a0
}