rule Win_Trojan_Overdoze_1
{
strings:
	$a0 = { 3d00fa771f2d03002ea3a301b440b9d601cd21b8004233c9cd21b440b90400baa201cd21b801572e }


condition:
	$a0
}