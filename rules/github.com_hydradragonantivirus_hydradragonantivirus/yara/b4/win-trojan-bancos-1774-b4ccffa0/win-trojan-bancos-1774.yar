rule Win_Trojan_Bancos_1774
{
strings:
	$a0 = { 3a5fa2da3020e1a7bb83eec531d9ebdc7830cd85a1177283f8e9836973edce547747aee51e7c9e2ae50cafd10e9794a73695728285cc22cb1db7e9e7ef6545545fc5a6e647c6 }


condition:
	$a0
}