rule Win_Trojan_Drepo_1
{
strings:
	$a0 = { f52e8a869b098bcd5381c108002e300481fa1ada4e3bf1 }


condition:
	$a0
}