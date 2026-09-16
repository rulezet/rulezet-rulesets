rule Win_Trojan_Grog_32
{
strings:
	$a0 = { 74d080fc3d74cb80fc5674c680fc4374c180fc4174 }


condition:
	$a0
}