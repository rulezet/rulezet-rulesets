rule Win_Trojan_Zmiana_1
{
strings:
	$a0 = { d23b5d1d2e90292a92a8289129284028b82f1bf3e53b5a3498a20ea0afd72990292b92a828912928 }


condition:
	$a0
}