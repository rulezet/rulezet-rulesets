rule Win_Trojan_SofiaTerminator_4
{
strings:
	$a0 = { 4b741a80fc3d741280fc41740d80fc56740880fc4374 }


condition:
	$a0
}