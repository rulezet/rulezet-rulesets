rule Win_Trojan_SillyC_185
{
strings:
	$a0 = { e80200eb108a966301b949018bfeac32c2aae2fa }


condition:
	$a0
}