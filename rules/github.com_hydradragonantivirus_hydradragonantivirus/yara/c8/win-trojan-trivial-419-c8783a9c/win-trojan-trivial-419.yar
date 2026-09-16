rule Win_Trojan_Trivial_419
{
strings:
	$a0 = { 33c9b44ecd210ac07540b8023dba9e00cd2193b80057cd21515250b43fb90100ba8901cd218bfa803dba7413b8 }


condition:
	$a0
}