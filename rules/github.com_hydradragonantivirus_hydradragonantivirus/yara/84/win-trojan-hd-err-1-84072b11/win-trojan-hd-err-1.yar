rule Win_Trojan_HD_ERR_1
{
strings:
	$a0 = { 13721dbebe80bfbe7db92100f3a559803eb77d00750fb80103bb007ccd137305be8a7deb5dfa }


condition:
	$a0
}