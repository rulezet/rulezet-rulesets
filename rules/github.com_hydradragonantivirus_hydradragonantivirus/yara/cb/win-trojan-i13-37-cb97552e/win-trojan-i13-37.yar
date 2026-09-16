rule Win_Trojan_I13_37
{
strings:
	$a0 = { 87064e002ea33701b8110187064c002ea33501b80102bb0002ba8000b901 }


condition:
	$a0
}