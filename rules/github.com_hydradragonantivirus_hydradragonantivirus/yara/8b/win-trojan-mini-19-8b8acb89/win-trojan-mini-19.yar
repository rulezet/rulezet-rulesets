rule Win_Trojan_Mini_19
{
strings:
	$a0 = { 0e5650568cc880c4108ec08bfeb97b00f3a4bad400b41acd21ba7501b44ecd21723dbaf200b8023dcd218bd8061f8bd749b43fcd21057b00813eba0144 }


condition:
	$a0
}