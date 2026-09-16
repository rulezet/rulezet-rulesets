rule Win_Trojan_SillyRC_9
{
strings:
	$a0 = { b82135cd21891ea6018c06a801bbfc00c707f3a4c706fe00eb005333db8ec3bf0002be0001b9ac009026803d4d740f }


condition:
	$a0
}