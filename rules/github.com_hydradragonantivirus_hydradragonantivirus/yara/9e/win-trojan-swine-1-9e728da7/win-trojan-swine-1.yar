rule Win_Trojan_Swine_1
{
strings:
	$a0 = { e177ff784bea6341d144e1b5f83524353c784be9329a7c50fd9d74bc5c63f918f1bc0503fe8e329a }


condition:
	$a0
}