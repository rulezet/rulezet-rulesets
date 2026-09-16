rule Win_Trojan_Freezer_1
{
strings:
	$a0 = { 750a81fb22117504b80096cf80fc3d740880fc4b7403e99700fc505351525657061eb80043 }


condition:
	$a0
}