rule Win_Trojan_Vienna_99
{
strings:
	$a0 = { 1e0683ea6e908bf28ccf8edf8ec7bf00015683c65f90b90300f3a45eb430cd213c027703e949013c067703e8 }


condition:
	$a0
}