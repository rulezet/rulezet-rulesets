rule Win_Trojan_Peed_162
{
strings:
	$a0 = { f7db87da750c5589e5ad83ee0546c9c20800e86c00000083c40383c401bf00764068bb }


condition:
	$a0
}