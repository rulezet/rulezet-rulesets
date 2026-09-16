rule Win_Trojan_Sofia_2
{
strings:
	$a0 = { 11742c80fc12742780fc4b74733dbebe74553d0378 }


condition:
	$a0
}