rule Win_Trojan_SVC_8
{
strings:
	$a0 = { 9dba9019cf5a1febbd33c08ec026c4 }


condition:
	$a0
}