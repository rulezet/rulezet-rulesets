rule Win_Trojan_Deathead_1
{
strings:
	$a0 = { 81ed080183fd00740dbe180701eebf0001b90500f3a4c6860f0700b41abae40601eacd21b44eba100701eacd217248 }


condition:
	$a0
}