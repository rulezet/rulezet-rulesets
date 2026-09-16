rule Win_Trojan_PrtF_1
{
strings:
	$a0 = { b81735cd218c068f018c066601891e8d01891e6401b81725ba2201cd21baec01cd27fa1e0e1f80 }


condition:
	$a0
}