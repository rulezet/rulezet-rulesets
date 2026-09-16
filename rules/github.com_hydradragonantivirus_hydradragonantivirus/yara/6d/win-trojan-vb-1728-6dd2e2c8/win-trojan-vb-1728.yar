rule Win_Trojan_VB_1728
{
strings:
	$a0 = { 642e4372657061746f0003900638130f0f17070f00002d4c }


condition:
	$a0
}