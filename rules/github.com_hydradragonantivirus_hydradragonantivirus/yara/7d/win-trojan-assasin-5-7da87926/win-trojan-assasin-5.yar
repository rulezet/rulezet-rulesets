rule Win_Trojan_Assasin_5
{
strings:
	$a0 = { e74abf6c8bdbe3aefb480ea1c4e4446022f1081d6f9ffbea3d5c6c451d20e1d4e1d748d15ae7f87d423bc9be8270361483f7c25aa9d95d2884371f9b01adf6bb }


condition:
	$a0
}