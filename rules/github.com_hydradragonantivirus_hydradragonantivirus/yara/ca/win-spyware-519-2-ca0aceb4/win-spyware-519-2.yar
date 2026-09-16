rule Win_Spyware_519_2
{
strings:
	$a0 = { d423773ed705fe834a85accaf8dedda09d75afbba604bd2f3dc73a3838711146d32c92585585ff64b6e476126ebe427e146070ff2bf6e5f98a51d3862bbb910ba05b69b2b31c50e4edf5cd }


condition:
	$a0
}