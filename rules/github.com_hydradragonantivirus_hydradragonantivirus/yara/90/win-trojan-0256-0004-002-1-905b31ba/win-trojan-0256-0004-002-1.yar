rule Win_Trojan__0256_0004_002_1
{
strings:
	$a0 = { 0643e88c01e87501b440b90500ba3406cd21b801572e8b163b062e8b0e3d06cd21b43ecd215a }


condition:
	$a0
}