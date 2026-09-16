rule Win_Trojan_Trivial_239
{
strings:
	$a0 = { ba2401b44ecd21b8023dba9e00cd218bd8b92a0090ba0001b440cd21b43ecd21b44febe1 }


condition:
	$a0
}