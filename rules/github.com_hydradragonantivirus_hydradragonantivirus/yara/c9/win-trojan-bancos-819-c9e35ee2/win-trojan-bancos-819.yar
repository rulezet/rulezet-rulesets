rule Win_Trojan_Bancos_819
{
strings:
	$a0 = { 6b26c5252606b77d51b94e30ee4af5debfa2cfeb536a6df6bd1ef5fe2a419811dd76406c4f88c266a9113fcdc32e8427eac857856516abb8bf4a116352ee25dc06a5ff1d0edf }


condition:
	$a0
}