rule Win_Trojan_VB_1082
{
strings:
	$a0 = { 4800540054005000200043006c00[0-14]50004f00530054 }

	$a1 = { 474554 }

	$a2 = { 48e5666c617368637078 }


condition:
	$a0 and $a1 and $a2
}