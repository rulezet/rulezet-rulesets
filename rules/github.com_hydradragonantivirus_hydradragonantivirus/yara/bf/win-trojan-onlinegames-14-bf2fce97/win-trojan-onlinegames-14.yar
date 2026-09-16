rule Win_Trojan_Onlinegames_14
{
strings:
	$a0 = { 575783c404890c24568bf1f7d687ce5e545959e8e46c010003d32bd3000000000000000000 }


condition:
	$a0
}