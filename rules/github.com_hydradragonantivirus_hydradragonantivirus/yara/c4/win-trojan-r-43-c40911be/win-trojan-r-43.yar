rule Win_Trojan_R_43
{
strings:
	$a0 = { 243d00fc771f2d03002ea35e03b440b96103cd21b8004233c9cd21b440b90400ba5d03cd }


condition:
	$a0
}