rule Win_Trojan_Birgit_17
{
strings:
	$a0 = { e2fdbaeb01ffd2c353bad301ffd25bb440b9eb00ba0001cd2153bad301ffd25bc3 }


condition:
	$a0
}