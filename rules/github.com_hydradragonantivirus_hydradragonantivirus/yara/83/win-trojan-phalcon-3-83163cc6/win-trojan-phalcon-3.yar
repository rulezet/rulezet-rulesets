rule Win_Trojan_Phalcon_3
{
strings:
	$a0 = { 033606018a24b9230483c62d908bfeac32c4aae2fa }


condition:
	$a0
}