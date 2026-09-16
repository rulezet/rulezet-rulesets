rule Win_Trojan_B_118
{
strings:
	$a0 = { 0402813f5cb3742abb0800c7070103c747020100c647040033dbe843003c0274a0 }


condition:
	$a0
}