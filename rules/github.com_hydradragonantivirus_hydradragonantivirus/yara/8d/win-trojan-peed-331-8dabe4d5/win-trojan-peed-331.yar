rule Win_Trojan_Peed_331
{
strings:
	$a0 = { 558bec51(53|56|57)(53|56|57)[0-30]6a00ff1500d04100 }


condition:
	$a0
}