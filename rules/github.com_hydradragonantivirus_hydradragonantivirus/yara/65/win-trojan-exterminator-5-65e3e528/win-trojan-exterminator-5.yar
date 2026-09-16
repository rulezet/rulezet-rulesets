rule Win_Trojan_Exterminator_5
{
strings:
	$a0 = { 27005589e531c09acd02270031c0a35200bf56011e57bfdb000e5731c0509a010727009add0527009a91022700 }


condition:
	$a0
}