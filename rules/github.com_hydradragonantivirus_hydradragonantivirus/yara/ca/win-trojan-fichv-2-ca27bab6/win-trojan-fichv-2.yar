rule Win_Trojan_Fichv_2
{
strings:
	$a0 = { cceb0e90ac3207aa433bda7203bb3101cf }


condition:
	$a0
}