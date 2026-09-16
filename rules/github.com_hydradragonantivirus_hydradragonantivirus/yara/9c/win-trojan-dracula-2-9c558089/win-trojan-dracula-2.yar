rule Win_Trojan_Dracula_2
{
strings:
	$a0 = { 5351525657551e069c3d004b740880fc3d7403e9f101 }


condition:
	$a0
}