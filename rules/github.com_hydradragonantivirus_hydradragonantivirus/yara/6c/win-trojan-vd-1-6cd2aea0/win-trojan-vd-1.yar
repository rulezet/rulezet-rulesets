rule Win_Trojan_VD_1
{
strings:
	$a0 = { 2ea300008cc02ea302008cd02ea304008bc42ea306008cd80510002e030610002ea310001e33c08ed8bb67048b07 }


condition:
	$a0
}