rule Win_Trojan_Clicker_37
{
strings:
	$a0 = { 5589e583ec0456578b750cbf0810400066ad6609c0740466abebf5 }


condition:
	$a0
}