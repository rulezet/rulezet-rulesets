rule Win_Trojan_SM_1
{
strings:
	$a0 = { 1fe10182fc5a59de1fe344fe5a5b1fd0f01003fec3c30c4163fcff4dff49ff0e4177613f3e7264 }


condition:
	$a0
}