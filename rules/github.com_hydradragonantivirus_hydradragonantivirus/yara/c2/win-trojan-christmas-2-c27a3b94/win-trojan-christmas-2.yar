rule Win_Trojan_Christmas_2
{
strings:
	$a0 = { 0a03590019000ee80000fa8bec5832c08946028146002800b9ce05b02a8846ff8b7600884efe8a4eff000ceb00468a4efee2 }


condition:
	$a0
}