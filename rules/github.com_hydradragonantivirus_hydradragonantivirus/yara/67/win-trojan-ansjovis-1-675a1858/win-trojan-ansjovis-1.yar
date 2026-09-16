rule Win_Trojan_Ansjovis_1
{
strings:
	$a0 = { 07e2f6fbf9fd35c2ba5053d1e9e8f809d1d1e307bfea8a04268605880417e934edc9f3d1c1033d }


condition:
	$a0
}