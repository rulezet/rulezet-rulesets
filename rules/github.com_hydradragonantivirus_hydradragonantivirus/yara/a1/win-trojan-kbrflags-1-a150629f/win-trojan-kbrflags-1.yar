rule Win_Trojan_Kbrflags_1
{
strings:
	$a0 = { 2e892e2403bc00048cd52e892e22038ccd8ed5501e060e1fa19003a39403a18e03a39203e9e80150535152565755 }


condition:
	$a0
}