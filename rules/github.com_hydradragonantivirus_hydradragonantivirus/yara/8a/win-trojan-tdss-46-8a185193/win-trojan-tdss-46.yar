rule Win_Trojan_TDSS_46
{
strings:
	$a0 = { 595e414949[0-100]414949[0-100]414949[0-100]414949 }


condition:
	$a0
}