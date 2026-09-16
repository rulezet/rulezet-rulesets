rule Win_Trojan_Delf_2191
{
strings:
	$a0 = { 1b4462a17f1103dbad4afc25817b3aaf413edf8d45fc4bc6a38127c3bb217e3bc3068a50b8ee81c40f7e0b6f71ff5006f68b84b2201000f853ec7a514b5d3f5ce9024c4bd1c7d128ebfca6 }


condition:
	$a0
}