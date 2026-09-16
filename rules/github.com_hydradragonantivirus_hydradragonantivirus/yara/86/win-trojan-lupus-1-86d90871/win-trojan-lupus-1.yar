rule Win_Trojan_Lupus_1
{
strings:
	$a0 = { 01b9ce012e8a1c80f38480eb38c0c3842e881c46e2ee }


condition:
	$a0
}