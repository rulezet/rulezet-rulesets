rule Win_Trojan_Brotherhood_1
{
strings:
	$a0 = { abcd9c505351521e06165657b42acd2180fe0b721880fe0c7f1380fa0b720e80fa197f09b409ba4e02cd21cd20a1e502a3e1028b1ee702891ee302b41a8d }


condition:
	$a0
}