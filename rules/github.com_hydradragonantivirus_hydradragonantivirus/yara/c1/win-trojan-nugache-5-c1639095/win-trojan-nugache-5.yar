rule Win_Trojan_Nugache_5
{
strings:
	$a0 = { 897a7c476df95e8f0ac119a101fecd1b7c31c562682f7a7f8e627a012d737c174b72a6b37a7f8e0562422b6afd57cd41c02f73fa8ae41e45f3c5df6f486a8e34ec394f8a11232b5bfe1f4e6a2b024b7d86 }


condition:
	$a0
}