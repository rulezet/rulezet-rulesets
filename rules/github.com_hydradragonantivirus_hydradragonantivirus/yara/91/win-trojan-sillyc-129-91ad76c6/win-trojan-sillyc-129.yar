rule Win_Trojan_SillyC_129
{
strings:
	$a0 = { 40b9f0008d960301cd213e8b860f022d03003e8986f301 }


condition:
	$a0
}