rule Win_Trojan_R_44
{
strings:
	$a0 = { 243d00fc771f2d03002ea36603b440b96903cd21b8004233c9cd21b440b90400ba6503cd }


condition:
	$a0
}