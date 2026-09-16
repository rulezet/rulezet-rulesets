rule Win_Spyware_Banker_2707
{
strings:
	$a0 = { 1bb502c991c197ceece14bb14ab704e47d5942d156dc57504cd2fe444effde060ef3d421b2370e27e16d82d21a040bd9ff2186333d53079f6a253eb061c50c8b2f6651c313b0dffd6ec2de2cdf81 }


condition:
	$a0
}