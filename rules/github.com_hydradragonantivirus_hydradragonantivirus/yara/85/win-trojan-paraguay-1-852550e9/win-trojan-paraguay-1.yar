rule Win_Trojan_Paraguay_1
{
strings:
	$a0 = { 1dac23d9cf353f07cf6101fd9b1404ac2321cf352c9d9c5a003a8e9252162c9d9c9c043a8e9288 }


condition:
	$a0
}