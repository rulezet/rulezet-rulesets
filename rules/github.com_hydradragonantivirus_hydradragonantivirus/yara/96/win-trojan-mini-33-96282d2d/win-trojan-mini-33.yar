rule Win_Trojan_Mini_33
{
strings:
	$a0 = { 01cd215a7218be0001bfcb01b90a00f3a7740b2e813ecb016d7a7402f8c3b43ecd21f9c3 }


condition:
	$a0
}