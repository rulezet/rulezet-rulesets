rule Win_Trojan_Peed_213
{
strings:
	$a0 = { 69c0cc5a0000eb0c5589e5ad83ee0546c9c20800e8480000005589e5890189d88b5d086bdb0383eb05c9c204 }


condition:
	$a0
}