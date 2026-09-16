rule Win_Trojan_B_88
{
strings:
	$a0 = { 8ed88ed0bc007cfbbf00048b45132d0300894513b106d3e08ec0b98a008bf433fff3a4bb2f00 }


condition:
	$a0
}