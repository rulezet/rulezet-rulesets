rule Win_Trojan_FatherMac_2
{
strings:
	$a0 = { 2601b9960689ff80c50081e9260188c089f6268a0280c4 }


condition:
	$a0
}