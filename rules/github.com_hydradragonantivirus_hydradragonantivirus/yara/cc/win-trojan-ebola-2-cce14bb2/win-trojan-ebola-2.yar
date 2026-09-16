rule Win_Trojan_Ebola_2
{
strings:
	$a0 = { 904d98f0404dbe0b0295fc4090f09095904db9ad0a4dfd400e4d954a901f37909020e480042bfd40904dfc20e4806c }


condition:
	$a0
}