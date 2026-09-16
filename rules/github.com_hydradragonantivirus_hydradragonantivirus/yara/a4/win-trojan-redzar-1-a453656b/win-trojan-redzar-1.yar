rule Win_Trojan_Redzar_1
{
strings:
	$a0 = { 9ec8023ec786ca02525ab9050051e83000b4408d96c70259cd21b8024233c999cd21b42ccd }


condition:
	$a0
}