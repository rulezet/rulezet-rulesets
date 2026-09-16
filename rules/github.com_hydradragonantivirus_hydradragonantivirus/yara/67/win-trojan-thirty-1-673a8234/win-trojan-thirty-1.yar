rule Win_Trojan_Thirty_1
{
strings:
	$a0 = { 8bd1cd6083c703893e0100b440b903002bd2cd60b802422bc9cd60b440b90d02cd60b43ecd60 }


condition:
	$a0
}