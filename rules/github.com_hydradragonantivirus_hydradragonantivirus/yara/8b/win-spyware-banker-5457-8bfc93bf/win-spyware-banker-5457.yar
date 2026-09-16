rule Win_Spyware_Banker_5457
{
strings:
	$a0 = { 4a0f63f87fae01590a08e2eecd839d3f98c9dc531cecb90b699c58f7c0a85ca69b84ac2395db690614fb2e6c477e2f7675bf3c170e397d39a2a59577de6a8403c2fb680c0bf79cdf2bbd65cc6a35 }


condition:
	$a0
}