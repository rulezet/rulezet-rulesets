rule Win_Trojan_Mayberry_9
{
strings:
	$a0 = { 96af038d96b203cd21b440b9ac02908d960601cd2132c0e828008d96ae03cd21 }


condition:
	$a0
}