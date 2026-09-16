rule Win_Trojan_Icommand_1
{
strings:
	$a0 = { 52019a0000ec0089e5c606900400e811fde847febf00021e57bf02021e57bf04021e57bf06021e579a1500c200 }


condition:
	$a0
}