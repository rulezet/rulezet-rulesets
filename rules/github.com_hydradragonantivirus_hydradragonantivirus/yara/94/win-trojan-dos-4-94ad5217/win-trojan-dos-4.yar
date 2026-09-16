rule Win_Trojan_DOS_4
{
strings:
	$a0 = { 13a18c138b168e13be00008ec626a38401be00008ec62689168601fbb06150bf94131e579a2201 }


condition:
	$a0
}