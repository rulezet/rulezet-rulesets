rule Win_Trojan_Packed_39
{
strings:
	$a0 = { 5589e56aff53565758585b585d60e81d }


condition:
	$a0
}