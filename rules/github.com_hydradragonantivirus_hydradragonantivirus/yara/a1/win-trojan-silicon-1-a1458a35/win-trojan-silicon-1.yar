rule Win_Trojan_Silicon_1
{
strings:
	$a0 = { 9c585b3bc37402cd200e171e06fc0e1fb42acd2180fe0c752b80fa057526b4098d964200cd }


condition:
	$a0
}