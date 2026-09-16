rule Win_Trojan_Leprosy_41
{
strings:
	$a0 = { 028b4718a344028b1e32028b4716a34602a13202051e }


condition:
	$a0
}