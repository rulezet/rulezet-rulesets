rule Win_Spyware_Banker_1462
{
strings:
	$a0 = { 970326c6e374ba82819c99d2c156aa0f14d2b900eeeb0543e17522bac33431b33035f457fb32c46454258ec0f0b8b3032e2e7c1a3e7cced7c3d10d46287fe60bcaf18e71 }


condition:
	$a0
}