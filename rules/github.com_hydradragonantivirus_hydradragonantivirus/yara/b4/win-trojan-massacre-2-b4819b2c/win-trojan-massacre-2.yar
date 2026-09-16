rule Win_Trojan_Massacre_2
{
strings:
	$a0 = { a3160489161404e86cfeb91c00ba1204b440e871fe8b0e30048b163204b80157cd21b43ecd215a }


condition:
	$a0
}