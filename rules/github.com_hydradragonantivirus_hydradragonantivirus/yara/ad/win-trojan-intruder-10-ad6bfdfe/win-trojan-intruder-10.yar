rule Win_Trojan_Intruder_10
{
strings:
	$a0 = { 42cd21c7062b004d00a14100a32d00c7062f005500a33100b90800ba2b00b440cd21b43ecd21 }


condition:
	$a0
}