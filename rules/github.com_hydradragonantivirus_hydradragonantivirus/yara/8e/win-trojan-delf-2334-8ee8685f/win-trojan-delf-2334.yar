rule Win_Trojan_Delf_2334
{
strings:
	$a0 = { 687474703a2f2f00ffffffff010000002f000000ffffffff09 }

	$a1 = { 22270000ffffffff040000002e657865 }

	$a2 = { 558becb9040000006a006a004975f951535657b80c974600e837cdf9ff33c055 }


condition:
	$a0 and $a1 and $a2
}