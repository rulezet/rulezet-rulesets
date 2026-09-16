rule Win_Trojan_Possessed_1
{
strings:
	$a0 = { 5f0372eeb8023de8570372e62ea3100a }


condition:
	$a0
}