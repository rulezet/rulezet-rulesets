rule Win_Trojan_Suspect_4
{
strings:
	$a0 = { 5b6175746f72756e5d[0-30]6f70656e3d[0-60]2e736372 }


condition:
	$a0
}