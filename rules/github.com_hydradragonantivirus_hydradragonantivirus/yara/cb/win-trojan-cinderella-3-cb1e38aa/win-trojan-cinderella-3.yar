rule Win_Trojan_Cinderella_3
{
strings:
	$a0 = { fc4b740880fc3d7403e9240253510656571e5250558bec }


condition:
	$a0
}