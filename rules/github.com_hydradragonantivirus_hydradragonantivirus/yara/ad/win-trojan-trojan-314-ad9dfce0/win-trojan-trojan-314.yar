rule Win_Trojan_Trojan_314
{
strings:
	$a0 = { c002b4088bd5cd1380e13f80e90732ed890e8401b80102bbc0028bf3b901008bd5cd1356bf5b01 }


condition:
	$a0
}