rule Win_Trojan_Digger_4
{
strings:
	$a0 = { b95802ba0000cd21721e90b8004233c933d2cd2190b440ba7400b90400cd2190b43ecd21 }


condition:
	$a0
}