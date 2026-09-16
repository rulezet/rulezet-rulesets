rule Win_Trojan_ITS_1
{
strings:
	$a0 = { 813efc0334127503e98400c706fc033412a184002ea30301a186002ea30501a124002ea30701a1 }


condition:
	$a0
}