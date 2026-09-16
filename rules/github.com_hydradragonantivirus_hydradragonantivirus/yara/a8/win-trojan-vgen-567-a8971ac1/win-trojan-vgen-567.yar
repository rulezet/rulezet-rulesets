rule Win_Trojan_VGEN_567
{
strings:
	$a0 = { 6f64756374696f6e73204c74642e0d0a245b5db4408d960001b9a702cd215355b003cf5b415243 }


condition:
	$a0
}