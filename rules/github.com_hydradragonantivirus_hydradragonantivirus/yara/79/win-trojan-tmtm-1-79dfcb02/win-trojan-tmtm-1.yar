rule Win_Trojan_Tmtm_1
{
strings:
	$a0 = { beed02bf4e02b96e00b0348a2432e08ac488254647e2f4eb0190e80000582d1d018bf00e1f0e0756b8bc0203c6bf00018bf0b90500fcf3a45ec784e4022e43b4 }


condition:
	$a0
}