rule Win_Trojan_Szoveg_1
{
strings:
	$a0 = { 032e8b16d3032ea3ae032e8916b00333d2b440b9bf03cd21726e3bc8756a2e813ebf034d5a }


condition:
	$a0
}