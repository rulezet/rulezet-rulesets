rule Win_Trojan_Vgen_80
{
strings:
	$a0 = { cd2068f23fb3711ace8a48c304bb175c9ed7524afa5890b32cf3db50da22ff2729 }


condition:
	$a0
}