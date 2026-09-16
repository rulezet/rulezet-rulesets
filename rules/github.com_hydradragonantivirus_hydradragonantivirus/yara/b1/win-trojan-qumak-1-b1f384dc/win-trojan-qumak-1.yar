rule Win_Trojan_Qumak_1
{
strings:
	$a0 = { fc4b740880fc3d74e0e9c2fe065053515657551e52e825 }


condition:
	$a0
}