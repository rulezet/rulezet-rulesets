rule Win_Trojan_U_91
{
strings:
	$a0 = { 48aadc40c7d910064b43150011c09b5b3d72372aac4c82c9ed96cc120db5a8a7cda4bae1f1371dd3 }


condition:
	$a0
}