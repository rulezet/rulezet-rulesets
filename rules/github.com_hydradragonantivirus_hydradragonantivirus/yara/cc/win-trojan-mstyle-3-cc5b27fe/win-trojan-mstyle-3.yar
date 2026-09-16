rule Win_Trojan_Mstyle_3
{
strings:
	$a0 = { 0c4f365ebd897ca7e29c4734b8fdd532e7994eff590c2c860e43b4872b22 }


condition:
	$a0
}