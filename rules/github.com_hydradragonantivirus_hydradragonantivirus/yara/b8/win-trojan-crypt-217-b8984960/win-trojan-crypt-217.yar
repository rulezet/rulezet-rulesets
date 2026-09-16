rule Win_Trojan_Crypt_217
{
strings:
	$a0 = { 558bec83c4f0535657b854964100e8f9bbfeffe828f2ffff33c0556836a3410064 }


condition:
	$a0
}