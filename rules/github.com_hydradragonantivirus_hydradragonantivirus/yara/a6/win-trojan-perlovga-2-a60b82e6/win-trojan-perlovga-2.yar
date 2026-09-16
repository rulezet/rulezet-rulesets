rule Win_Trojan_Perlovga_2
{
strings:
	$a0 = { 5b6175746f72756e5d0d0a5368656c6c657865637574653d636f70792e657865 }


condition:
	$a0
}