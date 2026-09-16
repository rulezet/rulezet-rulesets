rule Win_Trojan_Brian_2
{
strings:
	$a0 = { 66005589e581ec00018dbe00ff165731c0509afd056600bf72201e57bf7e201e57e81bfcbf56001e5731c031d2 }


condition:
	$a0
}