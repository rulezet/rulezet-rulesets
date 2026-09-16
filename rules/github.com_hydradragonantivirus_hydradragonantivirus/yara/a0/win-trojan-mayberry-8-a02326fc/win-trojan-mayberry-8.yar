rule Win_Trojan_Mayberry_8
{
strings:
	$a0 = { 023b166502744481c2610289166202ba6402cd21b440b95e0290ba0600cd2132c0 }


condition:
	$a0
}