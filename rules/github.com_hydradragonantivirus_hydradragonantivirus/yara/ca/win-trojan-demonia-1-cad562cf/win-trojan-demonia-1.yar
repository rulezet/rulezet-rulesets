rule Win_Trojan_Demonia_1
{
strings:
	$a0 = { 01b44eb90b11cd21907302eb11e83400ba8000b44fcd21907302eb02ebefb42acd213c02740bb409bade01cd21b44ccd21b456bafa01bfed01cd21b409ba }


condition:
	$a0
}