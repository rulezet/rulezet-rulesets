rule Win_Trojan_BootExe_1
{
strings:
	$a0 = { c8fa8ed0bc007cfb2e832e1304012ea11304b106d3e02d10008ec0be007c0e1fb900018bf9f2a5b830010650cbeb2ca14c002ea3ca01a14e002ea3cc018cc8 }


condition:
	$a0
}