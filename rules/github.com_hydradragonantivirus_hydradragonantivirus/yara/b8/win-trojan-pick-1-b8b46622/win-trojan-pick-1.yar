rule Win_Trojan_Pick_1
{
strings:
	$a0 = { 35005589e531c09acd023500e880fd5d31c09a1601350000558bec83ec501ec5760c8d7eb01607fcac3c4f7202 }


condition:
	$a0
}