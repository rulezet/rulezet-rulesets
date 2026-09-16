rule Win_Trojan_Ichthum_1
{
strings:
	$a0 = { 5756525153501ee87a003d091074165850488ed8e87500408ec00e1fe81cfee8baffe87d002ea011013c7d74190e }


condition:
	$a0
}