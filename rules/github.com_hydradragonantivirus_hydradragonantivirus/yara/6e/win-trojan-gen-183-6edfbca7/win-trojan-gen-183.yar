rule Win_Trojan_Gen_183
{
strings:
	$a0 = { 7403e92901803ed9152e7503e91201c68693f901803efb1500741cbf06171e57bfd815 }


condition:
	$a0
}