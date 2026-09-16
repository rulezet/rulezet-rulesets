rule Win_Trojan_RiotEnemy_1
{
strings:
	$a0 = { cd21bff503891ef5038c06f703ba1b01b425cd218bd7cd273d004b74083d003d7403e9cc02e99302 }


condition:
	$a0
}