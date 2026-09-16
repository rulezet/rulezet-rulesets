rule Win_Trojan_Small_4458
{
strings:
	$a0 = { 68??76400089e08b005068ccf8ffffe86400 }


condition:
	$a0
}