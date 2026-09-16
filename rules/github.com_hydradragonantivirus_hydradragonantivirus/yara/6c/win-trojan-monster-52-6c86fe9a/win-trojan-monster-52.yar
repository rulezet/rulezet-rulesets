rule Win_Trojan_Monster_52
{
strings:
	$a0 = { b9e001be????8034??46e2faeb15 }


condition:
	$a0
}