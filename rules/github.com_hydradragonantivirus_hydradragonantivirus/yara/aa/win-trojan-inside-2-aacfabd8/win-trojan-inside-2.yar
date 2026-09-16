rule Win_Trojan_Inside_2
{
strings:
	$a0 = { 903da1f1741a3d004b741280fc56740d80fc3d740880fc437403e93c02e9c100b8ffa1cf1e53511e060e1f0e07e8 }


condition:
	$a0
}