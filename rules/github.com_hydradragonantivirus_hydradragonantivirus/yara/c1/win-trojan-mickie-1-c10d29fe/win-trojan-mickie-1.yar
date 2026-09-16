rule Win_Trojan_Mickie_1
{
strings:
	$a0 = { cd207508030607018ed8eb028ed8b91401be31 }


condition:
	$a0
}