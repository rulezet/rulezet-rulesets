rule Win_Trojan_VGEN_199
{
strings:
	$a0 = { 90bd0400cd038d8e5603ffd1765ffbb6eff370e6cdf350e5cdf748e0cd8139a739a735fc15f8077b765febf6583ccfb6ef }


condition:
	$a0
}