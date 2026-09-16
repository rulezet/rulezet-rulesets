rule Win_Trojan_Delf_2333
{
strings:
	$a0 = { 696f6e5c52756e }

	$a1 = { 6d6f727068[0-11]6b65792e747874 }

	$a2 = { 558bec83c4f05356b8d8644e00e8fa08f2ffbb54c34e008b }


condition:
	$a0 and $a1 and $a2
}