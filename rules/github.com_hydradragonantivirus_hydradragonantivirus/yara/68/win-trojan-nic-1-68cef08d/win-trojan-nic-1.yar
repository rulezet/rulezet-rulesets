rule Win_Trojan_Nic_1
{
strings:
	$a0 = { 08284f3e4febaf89ec5d22c0279a160116015500008bec83ec501ec5760c8d7eb01607fcac }


condition:
	$a0
}