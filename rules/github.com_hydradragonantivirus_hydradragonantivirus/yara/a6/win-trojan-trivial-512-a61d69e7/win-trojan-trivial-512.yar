rule Win_Trojan_Trivial_512
{
strings:
	$a0 = { 7001b44ee80a00ba7401b43bcd2173efc3cd21722eb002b43dba9e00cd2193be2f02bf3a02b90b00a4e2fdba3a02ff }


condition:
	$a0
}