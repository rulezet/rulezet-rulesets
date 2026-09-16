rule Win_Trojan_Rainbow_10
{
strings:
	$a0 = { 6800011e0660e800005d83ed0a0e1f8db674088b043d4d5a9c741a407510bf060003f7ff348bdc }


condition:
	$a0
}