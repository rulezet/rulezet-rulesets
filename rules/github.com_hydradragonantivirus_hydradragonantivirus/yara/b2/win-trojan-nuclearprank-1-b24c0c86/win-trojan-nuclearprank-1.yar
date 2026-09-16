rule Win_Trojan_NuclearPrank_1
{
strings:
	$a0 = { 5553bd1cb4d40a25de80bd3a001d273c0aca0cf4dfe2accd0b99260bf8fe409b0208973c545d9e4c0e2e860fdd341ff482408c110f5a12ddd8904819578af484708011e1e9acc21ab0e0cbb7f23084fc }


condition:
	$a0
}