rule Win_Trojan_Bancos_1768
{
strings:
	$a0 = { 57b675b628edbe583f2be6d5bfc5ec7d04eb1cc9d8445c9667aeebeb2398b469e56d122b7214403d01835a05c0b423cc3d843761a3710d3beadd781bb153d61224f620e2b77b }


condition:
	$a0
}