rule Win_Trojan_V_78
{
strings:
	$a0 = { 03721e33d2b99802b440e83900721233c9b80042e82f008bd6b90300b440e825005a59b801 }


condition:
	$a0
}