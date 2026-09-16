rule Win_Trojan_SdBot_3639
{
strings:
	$a0 = { bb4dc6d1a1824e47c325660fe9294ed0c46ddd6187b2f7475a64681e9e4d8c9188d99dfaf988be9076cc969d77983ea0022796abcb7d1a5d69a9664a869b270dbdd5a0eee51f38a16fa7e12aec48 }


condition:
	$a0
}