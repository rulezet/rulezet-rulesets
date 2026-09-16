rule Win_Trojan_Oops_1
{
strings:
	$a0 = { 02cd21cd209c80fc967504b4699dcf3d004b7503e806 }


condition:
	$a0
}