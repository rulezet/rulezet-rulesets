rule Win_Trojan_BHO_106
{
strings:
	$a0 = { 558bec83ec545333db43395d0c8da4e4fcffffff897424008d6464fc89bc24 }

	$a1 = { 8b3c64ffd0683f42325e8104646d }


condition:
	$a0 and $a1
}