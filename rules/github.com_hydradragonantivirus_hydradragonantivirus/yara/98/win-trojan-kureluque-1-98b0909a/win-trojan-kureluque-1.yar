rule Win_Trojan_Kureluque_1
{
strings:
	$a0 = { ed0301cc565e4c4c5f2bf774042ecd1990b8addecd213dbebe7455b82135cd212e8c864c022e899e4a028cd8488e }


condition:
	$a0
}