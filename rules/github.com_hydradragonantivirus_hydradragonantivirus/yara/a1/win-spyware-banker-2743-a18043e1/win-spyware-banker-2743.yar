rule Win_Spyware_Banker_2743
{
strings:
	$a0 = { 70c02aafc1164dec6453516fccaad2d6294b149a9e2211f659fce88006a264e5a12386bb5f4398ce5272a782f2c42d917ccc092ebac3b65564b7 }


condition:
	$a0
}