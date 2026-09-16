rule Win_Trojan_E_32
{
strings:
	$a0 = { 33c0fcf3ae7556c607e98a47022ea2fc02c747019d }


condition:
	$a0
}