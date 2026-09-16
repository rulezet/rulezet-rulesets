rule Win_Trojan_B_30
{
strings:
	$a0 = { 148b4c02b80102e84a0072f3ea007c00000eb413cd2f1f8c063801891e36010e07b801028b }


condition:
	$a0
}