rule Win_Trojan_Motu_1
{
strings:
	$a0 = { 0fa3d8aafd141228fa14fc1406ff1314bfe1040abf8e0a745c813ecd8262687554fec303027b }


condition:
	$a0
}