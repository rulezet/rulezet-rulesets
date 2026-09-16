rule Win_Trojan_R_39
{
strings:
	$a0 = { 0872243d00fc771f2d03002ea39802b440b99b02cd21b8004233c9cd21b440b90400ba9702cd }


condition:
	$a0
}