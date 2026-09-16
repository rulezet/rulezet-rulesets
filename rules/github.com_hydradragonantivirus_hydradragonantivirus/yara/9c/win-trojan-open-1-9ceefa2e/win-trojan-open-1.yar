rule Win_Trojan_Open_1
{
strings:
	$a0 = { 0300ba9600cd2158e8d3fe7303e969fe26894515b440b99f0433d2cd21e959fe837c1a0074 }


condition:
	$a0
}