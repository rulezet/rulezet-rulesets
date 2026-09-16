rule Win_Trojan_Caphaw_1
{
strings:
	$a0 = { 50e8d12f0000595ec3558bec81ec480200005356578b7d0c33f68a1f4784db8975f48975ec897d0c }


condition:
	$a0
}