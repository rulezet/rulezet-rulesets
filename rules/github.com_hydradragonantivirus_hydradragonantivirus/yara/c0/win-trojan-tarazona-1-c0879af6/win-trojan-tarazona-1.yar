rule Win_Trojan_Tarazona_1
{
strings:
	$a0 = { 07e800008bf4368b1c81eb120183c4028beb505351525657061ee9a603b9960333ff3e80b33a0103474975f6b9 }


condition:
	$a0
}