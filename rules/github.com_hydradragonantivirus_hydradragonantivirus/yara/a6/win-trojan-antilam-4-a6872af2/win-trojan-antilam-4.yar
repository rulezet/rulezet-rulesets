rule Win_Trojan_Antilam_4
{
strings:
	$a0 = { 1f0000004b65796c6f676765722061e7fd6cfd726b656e2068617461206f6c75fe747500b201 }


condition:
	$a0
}