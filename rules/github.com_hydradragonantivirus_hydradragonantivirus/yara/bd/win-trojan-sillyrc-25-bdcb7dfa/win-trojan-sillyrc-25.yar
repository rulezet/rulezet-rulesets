rule Win_Trojan_SillyRC_25
{
strings:
	$a0 = { 50e800005eb8fe35cd2181fb01107449ba0110b425cd218c }


condition:
	$a0
}