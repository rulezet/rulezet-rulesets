rule Win_Trojan_Banker_6347
{
strings:
	$a0 = { 480054005400500053 }

	$a1 = { 5000550054 }

	$a2 = { 43004f004e004e004500430054 }

	$a3 = { 4700450054 }

	$a4 = { 2f00720032006e006500770069 }


condition:
	$a0 and $a1 and $a2 and $a3 and $a4
}