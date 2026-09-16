rule Win_Trojan_Bancos_1906
{
strings:
	$a0 = { 02afeac1e12fb147532713deb4442943633be8dac69729bd2b7ca485e3dfe72b5d110b7b0b09a7177817eef07ee6ab0eaaf6cd00434f5976fabd49c2fa97d9c75532b8e8c401 }


condition:
	$a0
}