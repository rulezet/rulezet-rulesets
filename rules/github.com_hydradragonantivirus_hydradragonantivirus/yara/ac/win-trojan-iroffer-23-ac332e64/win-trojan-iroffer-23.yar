rule Win_Trojan_Iroffer_23
{
strings:
	$a0 = { ff45ec837dec050f8ef1feffff8b55f0b9c0d04200894c2404891424e879faffff83c42c5b5e5f5d }


condition:
	$a0
}