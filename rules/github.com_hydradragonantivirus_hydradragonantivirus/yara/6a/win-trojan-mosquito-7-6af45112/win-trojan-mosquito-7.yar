rule Win_Trojan_Mosquito_7
{
strings:
	$a0 = { 51032e8a242e32265d012e88244681fe7a0375ee58 }


condition:
	$a0
}