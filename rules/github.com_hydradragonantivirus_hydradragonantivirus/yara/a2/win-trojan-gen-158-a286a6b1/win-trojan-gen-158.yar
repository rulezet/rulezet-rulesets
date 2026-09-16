rule Win_Trojan_Gen_158
{
strings:
	$a0 = { b3009a0d0035005589e581ec0202bf2b020e57bfaa011e57b8ff00509afa06b300bfaa011e57e860ffb440bb01 }


condition:
	$a0
}