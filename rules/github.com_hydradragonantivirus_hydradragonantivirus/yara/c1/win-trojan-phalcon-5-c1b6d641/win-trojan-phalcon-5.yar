rule Win_Trojan_Phalcon_5
{
strings:
	$a0 = { 033606018a24b9550481c62e008bfeac32c4aae2fa }


condition:
	$a0
}