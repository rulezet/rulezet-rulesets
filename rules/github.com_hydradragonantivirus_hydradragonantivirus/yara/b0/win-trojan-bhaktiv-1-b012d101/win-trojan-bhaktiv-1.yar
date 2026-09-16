rule Win_Trojan_Bhaktiv_1
{
strings:
	$a0 = { 80fc4b74123d003d740d3d006c7505 }


condition:
	$a0
}