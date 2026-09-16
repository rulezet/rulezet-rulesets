rule Win_Trojan_Alman_5
{
strings:
	$a0 = { 33d8cc5bb99e04000080??19??e2faeb06e8edfffffffc }


condition:
	$a0
}