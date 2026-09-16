rule Win_Trojan_Tic_3
{
strings:
	$a0 = { 568cc880c4108ec033ffb96d00f3a4ba00feb41acd21ba6701b44eeb06b43ecd21b44f0e1fcd21b91efe72288bd1b8023dcd2193061f8bd7b43fcd2105 }


condition:
	$a0
}