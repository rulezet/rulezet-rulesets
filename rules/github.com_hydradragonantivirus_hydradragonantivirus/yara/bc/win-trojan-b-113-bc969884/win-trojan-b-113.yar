rule Win_Trojan_B_113
{
strings:
	$a0 = { 8ed88ec0bf0800b98401fc8a050461aae2f9e9e3fe }


condition:
	$a0
}