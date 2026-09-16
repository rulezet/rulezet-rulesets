rule Win_Trojan_Zbot_1256
{
strings:
	$a0 = { 29f739ef408d1c386a00ff15ea8441005081f34ee500008d1c088d0c045931d8 }


condition:
	$a0
}