rule Win_Trojan_Alman_1
{
strings:
	$a0 = { eb1133d8cc5bb9ad020000803419??e2faeb06e8edfffffffc }


condition:
	$a0
}