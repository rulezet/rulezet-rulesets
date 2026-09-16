rule Win_Trojan_Bancos_702
{
strings:
	$a0 = { 4a1f2a253019b2a61c7baf3241a165be523c290009f13c3ecdfa6f9c3339f545aedc154ade376e9d88cd099a370edcb0128e5df7f44a2a85696be2d76b0cc6a7c99ca111dd169fade63dd2cd }


condition:
	$a0
}