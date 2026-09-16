rule Win_Trojan_Spanish_1
{
strings:
	$a0 = { 2906e8e005b419cd218884e300e8ce }


condition:
	$a0
}