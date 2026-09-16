rule Win_Trojan_ExeBug_4
{
strings:
	$a0 = { c08ed88ec0fa8ed0b8007c89c4fb31c0cd13b80102bb007e8b0e077c498b16097ccd13a113042d4000b106d3e08ec0 }


condition:
	$a0
}