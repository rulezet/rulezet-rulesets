rule Win_Trojan_VB_755
{
strings:
	$a0 = { 25755c25732e646c6c[0-171]434c5349445c2573 }

	$a1 = { 25732e25735c437572566572 }

	$a2 = { 504153537b6675636b65647d }


condition:
	$a0 and $a1 and $a2
}