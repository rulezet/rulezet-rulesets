rule Win_Trojan_Killsys_2
{
strings:
	$a0 = { 6563686f204064656c206b65726e656c33322e646c6c3e3e6175746f657865632e626174 }


condition:
	$a0
}