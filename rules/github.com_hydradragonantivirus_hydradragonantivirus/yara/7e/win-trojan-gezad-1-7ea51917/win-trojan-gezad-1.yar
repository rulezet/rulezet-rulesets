rule Win_Trojan_Gezad_1
{
strings:
	$a0 = { 64284000000000004745445a41430000466f726d31000000fe696294dd355e4fbbfbc84f565f1db8deebe3641d6ad14a }


condition:
	$a0
}