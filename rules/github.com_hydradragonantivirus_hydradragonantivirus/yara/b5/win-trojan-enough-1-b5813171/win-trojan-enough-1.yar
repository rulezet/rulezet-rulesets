rule Win_Trojan_Enough_1
{
strings:
	$a0 = { 8176000b1845454a75f5e3180b40260c0b93e3060da04a5cc639364b5b6c639be818bf5240d52a9be04abf52c639794f8836 }


condition:
	$a0
}