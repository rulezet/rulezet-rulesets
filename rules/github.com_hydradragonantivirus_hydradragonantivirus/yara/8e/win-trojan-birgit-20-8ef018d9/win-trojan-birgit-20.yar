rule Win_Trojan_Birgit_20
{
strings:
	$a0 = { e2fdba0102ffd2c353bae901ffd25bb440b90101ba0001cd2153bae901ffd25bc3 }


condition:
	$a0
}