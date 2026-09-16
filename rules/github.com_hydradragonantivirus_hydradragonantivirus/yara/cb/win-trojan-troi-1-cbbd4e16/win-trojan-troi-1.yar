rule Win_Trojan_Troi_1
{
strings:
	$a0 = { cd2181f9c8077211770681fa01057209b4fccd2180fc55751c071f8cc805 }


condition:
	$a0
}