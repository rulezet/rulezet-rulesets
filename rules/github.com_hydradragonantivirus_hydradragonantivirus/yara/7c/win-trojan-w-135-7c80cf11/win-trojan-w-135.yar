rule Win_Trojan_W_135
{
strings:
	$a0 = { 44c67d61a896c09d74bb6dbc6ba0a657c87677640c7e9a2fb8d2cdbca3a033503b903b1f46e9b27fe4d028134efa923eccd1c392951c5edaaf459144ee }


condition:
	$a0
}