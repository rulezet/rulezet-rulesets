rule Win_Trojan_Taiwan_8
{
strings:
	$a0 = { eb7eedd8cfcfdec3c4cdd98accd8c5c78ae4cbdec3c5c4cbc68ae9cfc4ded8cbc68affc4c3dccfd8d9c3ded38a8be3d98adec5cecbd38ad9dfc4c4d38a950a0d }


condition:
	$a0
}