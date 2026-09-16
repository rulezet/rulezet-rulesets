rule Win_Trojan_BOO_20
{
strings:
	$a0 = { 41e8150050508db4af02bf00015766a533c0c3b80102b90100ba8000cd13c383ea21cfebfa }


condition:
	$a0
}