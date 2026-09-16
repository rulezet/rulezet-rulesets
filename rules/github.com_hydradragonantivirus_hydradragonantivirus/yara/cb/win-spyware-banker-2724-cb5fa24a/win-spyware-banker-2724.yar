rule Win_Spyware_Banker_2724
{
strings:
	$a0 = { 06cbd0d812a57750137aa8b953a1c04f55e9754b8a478294297cced7ee87e1e00d45596d584578a92e16c1f948cedd96583e0c4083ec82a9e318 }


condition:
	$a0
}