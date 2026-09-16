rule Win_Trojan_Loz_8
{
strings:
	$a0 = { f3a407b449cd21bb0000b90100ba8000b80102cd1326fe87e300b80103cd132680bfe300e0 }


condition:
	$a0
}