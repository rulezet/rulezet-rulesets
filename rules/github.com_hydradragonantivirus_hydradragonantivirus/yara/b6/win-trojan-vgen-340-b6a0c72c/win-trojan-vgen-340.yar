rule Win_Trojan_VGEN_340
{
strings:
	$a0 = { 179c58f6c4017403e998001eb002e6218cda83c2108eda8ec2bbb011ba000085d27429b40133ff33f6b900f0ac32c4 }


condition:
	$a0
}