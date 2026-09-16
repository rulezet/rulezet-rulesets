rule Win_Trojan_Alman_3
{
strings:
	$a0 = { 33c085c0740fcc5bb9ad020000??????????faeb06 }


condition:
	$a0
}