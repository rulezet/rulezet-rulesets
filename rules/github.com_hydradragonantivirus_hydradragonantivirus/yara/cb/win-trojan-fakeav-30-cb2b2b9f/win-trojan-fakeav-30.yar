rule Win_Trojan_Fakeav_30
{
strings:
	$a0 = { 515356576a406800300000ff35681241006a00e8cb0300006a118bf05bbf9012 }


condition:
	$a0
}