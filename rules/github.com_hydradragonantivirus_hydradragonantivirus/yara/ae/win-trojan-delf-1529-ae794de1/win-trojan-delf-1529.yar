rule Win_Trojan_Delf_1529
{
strings:
	$a0 = { 558bec83c4f0535657b81c2d0110e85d28ffff33c05568d22e011064ff30648920e8d62affffe8f52cffff6a0a68e42e0110 }


condition:
	$a0
}