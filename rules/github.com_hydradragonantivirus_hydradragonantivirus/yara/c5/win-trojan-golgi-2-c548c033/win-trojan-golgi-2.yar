rule Win_Trojan_Golgi_2
{
strings:
	$a0 = { 01b83d4dcd213d3d007461991e06521fc53684002e89b6e4012e8c9ee601 }


condition:
	$a0
}