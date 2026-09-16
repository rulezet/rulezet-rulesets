rule Win_Trojan_Delta_1
{
strings:
	$a0 = { be230003f58bfeb95d043e8a6604fcac32c4aae2fa }


condition:
	$a0
}