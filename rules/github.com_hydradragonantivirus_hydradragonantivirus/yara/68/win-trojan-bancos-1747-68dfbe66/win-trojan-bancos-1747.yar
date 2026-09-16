rule Win_Trojan_Bancos_1747
{
strings:
	$a0 = { 957e739d1b68c08db717cf2deed4c1bc4e731ec8acbd33555cbb07da896b2f4f88cc76dd4f9fde1c348a57e0c119b906d682049bf6b98cd0753e845ea7fa369143f09e6e4a26 }


condition:
	$a0
}