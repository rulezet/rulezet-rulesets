rule Win_Trojan_Jerusalem_55
{
strings:
	$a0 = { fcb4e0cd2180fce0731780fc037212b4ddbf00018d36????03f72e8b0e????cd218cc80510008ed08d26????508d06????50cb }


condition:
	$a0
}