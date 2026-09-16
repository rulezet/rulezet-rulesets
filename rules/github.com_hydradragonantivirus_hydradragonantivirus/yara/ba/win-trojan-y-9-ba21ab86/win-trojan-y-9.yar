rule Win_Trojan_Y_9
{
strings:
	$a0 = { b90100ba8000bb1302cd13b80102fec4505141cd138bfbb8eb2bfcabe831005958cd13ea }


condition:
	$a0
}