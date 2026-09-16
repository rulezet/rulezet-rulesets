rule Win_Trojan_Mybot_287
{
strings:
	$a0 = { edf9176b75616e67324b13ef7e2197079443dc2473756237e5109b }


condition:
	$a0
}