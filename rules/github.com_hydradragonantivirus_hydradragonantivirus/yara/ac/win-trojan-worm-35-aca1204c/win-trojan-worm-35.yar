rule Win_Trojan_Worm_35
{
strings:
	$a0 = { 72e38d75f6ff7508e884ffffffc745f000000000eb21ac50e844ffffff8845eb6a008d45ec506a018d45eb50ff7510e8 }

	$a1 = { ff75fce838ffffff0bc07402eb26bf03000000ff75f4ff75f8ff75fce8e8faffff85c075034f7feb0bc074 }

	$a2 = { c974068bde8ac8ebc88bc35b5ec9c20400558bec8b450c2b450883f8027c09b801000000c9c2080033c0c9 }


condition:
	$a0 and $a1 and $a2
}