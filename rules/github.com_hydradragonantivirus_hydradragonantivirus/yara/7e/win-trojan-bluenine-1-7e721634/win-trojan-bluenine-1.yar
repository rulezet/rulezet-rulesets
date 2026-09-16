rule Win_Trojan_BlueNine_1
{
strings:
	$a0 = { 33c933d2e82b00c353b8ba10359a02cd2f721c26803dff741633db268a1db88c10359a02cd2f }


condition:
	$a0
}