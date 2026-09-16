rule Win_Trojan_Monster_15
{
strings:
	$a0 = { 02be7e1180346d46e2faeb24364d2022233e39283f4d30316d4743476d47432e22206d52f7e484007d6d7c65f97d }


condition:
	$a0
}