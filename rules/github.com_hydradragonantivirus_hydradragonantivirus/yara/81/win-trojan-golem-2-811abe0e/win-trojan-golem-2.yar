rule Win_Trojan_Golem_2
{
strings:
	$a0 = { 609ce800000000582d071040008d??31104000??1c0000008b??20104000eb04 }


condition:
	$a0
}