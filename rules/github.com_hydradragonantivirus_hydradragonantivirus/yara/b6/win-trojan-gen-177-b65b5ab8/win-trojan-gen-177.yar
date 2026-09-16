rule Win_Trojan_Gen_177
{
strings:
	$a0 = { 30005589e5bfdb010e57bf52001e57b8ff00509aa2083000bf52001e57e802ffbf52131e57bf52001e5731c050 }


condition:
	$a0
}