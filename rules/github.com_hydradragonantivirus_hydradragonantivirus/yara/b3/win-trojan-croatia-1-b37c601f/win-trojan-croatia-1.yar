rule Win_Trojan_Croatia_1
{
strings:
	$a0 = { c3b8023de82400c3b8003de81d00c3b43fb940008b1e1201ba4506e80d00c3b440e80700c3 }


condition:
	$a0
}