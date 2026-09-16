rule Win_Trojan_Stoned_51
{
strings:
	$a0 = { b801038bffbb0002b90300b6019cff1eaa017212b8010333dbbb0000b9010032f69cff1eaa01 }


condition:
	$a0
}