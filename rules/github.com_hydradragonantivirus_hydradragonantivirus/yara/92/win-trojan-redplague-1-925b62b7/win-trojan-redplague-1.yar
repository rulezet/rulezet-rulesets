rule Win_Trojan_RedPlague_1
{
strings:
	$a0 = { a09bb62ba093592a94312d89cfd0a0bb592ad2ffee7ea0bb9a2bd2ff76996d94622ba0bb092ce00c7ea0bb9a2bd2ff76ee2e8aa6ca068db6f102b9c6032e302446e2fac32d }


condition:
	$a0
}