rule Win_Trojan_Mini_31
{
strings:
	$a0 = { 02b90300cd217303eb54908d5e028b1f81fb4d5a74 }


condition:
	$a0
}