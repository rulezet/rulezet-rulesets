rule Win_Trojan_Zebra_1
{
strings:
	$a0 = { ba3bd6b0bdd7bad2b6b0d03bbab6b0d73bbad7d20002200d00008db626008dbe2e00b8e001ffd0 }


condition:
	$a0
}