rule Win_Trojan_DiskKiller_3
{
strings:
	$a0 = { 0b00a14200a346008b1644008916480051e85600b9030051b001e89c00597308b400cd13e2f1 }


condition:
	$a0
}