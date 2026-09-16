rule Win_Trojan_Doggy_1
{
strings:
	$a0 = { 58a35c055c182a2e657803182e23c61c6374e21a182318d97eb00dc03c4f7202e318581bc68622 }


condition:
	$a0
}