rule Win_Trojan_Shit_1
{
strings:
	$a0 = { 9a00008a005589e5b800029acd028a0081ec0002e884fcbf5a031e57bf89050e5731c0509a70068a008dbe00fe16578d }


condition:
	$a0
}