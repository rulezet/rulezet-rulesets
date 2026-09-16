rule Win_Trojan_Wolleh_1
{
strings:
	$a0 = { 9f8ec0b402b004bb0001b54fb10cb601b200cd13ea0001009f }


condition:
	$a0
}