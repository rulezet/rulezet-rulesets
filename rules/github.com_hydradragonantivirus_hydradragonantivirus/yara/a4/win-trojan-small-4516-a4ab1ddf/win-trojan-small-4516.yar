rule Win_Trojan_Small_4516
{
strings:
	$a0 = { 89e08b401c8d8062??7504506862343504e84a000000508d15315b5604525051 }


condition:
	$a0
}