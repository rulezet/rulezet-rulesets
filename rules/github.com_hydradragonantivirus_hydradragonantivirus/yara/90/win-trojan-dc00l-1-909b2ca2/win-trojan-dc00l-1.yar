rule Win_Trojan_DC00L_1
{
strings:
	$a0 = { 01033606018a24b9d90683c62d908bfeac32c4aae2fac356e8e3ffb913075a83c2b590b440cd }


condition:
	$a0
}