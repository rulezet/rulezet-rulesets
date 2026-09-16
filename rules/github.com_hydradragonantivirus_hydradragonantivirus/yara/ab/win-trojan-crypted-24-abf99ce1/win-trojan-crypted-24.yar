rule Win_Trojan_Crypted_24
{
strings:
	$a0 = { 60e8000000005b6633db8bc303403c0fb750148d44101883c0288b400c03c305 }


condition:
	$a0
}