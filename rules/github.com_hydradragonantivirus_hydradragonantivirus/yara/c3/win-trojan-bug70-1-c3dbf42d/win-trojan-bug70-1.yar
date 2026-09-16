rule Win_Trojan_Bug70_1
{
strings:
	$a0 = { cd13730e2efe0620022e803e20020575e6f9c32ec606200200b80103bb007cbe0a07cd1373 }


condition:
	$a0
}