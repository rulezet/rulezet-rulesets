rule Win_Trojan_LoveChild_1
{
strings:
	$a0 = { 33c08ec0e800005e8beebfe001fc2681 }


condition:
	$a0
}