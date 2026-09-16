rule Win_Trojan_ZhengZhou_4
{
strings:
	$a0 = { 07be1407bf83012bf78bce418bf7fcac32062701aae4210c02e621e2f2be890bbf67082bf7 }


condition:
	$a0
}