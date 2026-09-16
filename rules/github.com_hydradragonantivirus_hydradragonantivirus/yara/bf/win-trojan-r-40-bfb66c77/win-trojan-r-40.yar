rule Win_Trojan_R_40
{
strings:
	$a0 = { 243d00fc771f2d03002ea3f102b440b9f402cd21b8004233c9cd21b440b90400baf002cd }


condition:
	$a0
}