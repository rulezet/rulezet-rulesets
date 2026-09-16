rule Win_Trojan_BW_7
{
strings:
	$a0 = { b9f102908d960601cd2132c0e828008d96f303cd215a }


condition:
	$a0
}