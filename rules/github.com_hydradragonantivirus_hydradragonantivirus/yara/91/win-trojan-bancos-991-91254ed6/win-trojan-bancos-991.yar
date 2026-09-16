rule Win_Trojan_Bancos_991
{
strings:
	$a0 = { 4e449b04e32a532ece84cfb2badbdbbd9d812cc1ce411e926a4d9ca976c61a20fb84a0537c5a14115e8eb34d2caddaf7e8c762bdce9076cb518912974c23a4bcf40c78d9bf6afc83d59a3238168d85665744 }


condition:
	$a0
}