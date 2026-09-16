rule Win_Spyware_Trimere_1
{
strings:
	$a0 = { 558bec81ec98000000c78570ffffffbc6d46006a006a008d856cffffff508d8d68ffffff51e82affffff }


condition:
	$a0
}