rule Win_Trojan_Morgoth_3
{
strings:
	$a0 = { e800005d05ebf98d761190eb0790904646e2fac3e815028db62f02bf0001fca4a506b82435cd212e8c0670fa2e89 }


condition:
	$a0
}