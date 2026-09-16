rule Win_Trojan_L_16
{
strings:
	$a0 = { d2b92c0781e91d012d0000268a0283e90088c034002688024680c400e2ed80ef0080c400c3 }


condition:
	$a0
}