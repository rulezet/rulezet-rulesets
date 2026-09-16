rule Win_Trojan_NoFrills_2
{
strings:
	$a0 = { 32547504b80710cf80fc4b741880fc3d741380fc43740e }


condition:
	$a0
}