rule Win_Trojan_Hi_2
{
strings:
	$a0 = { 33c933d2b80042cd21ba0800b90500b440cd21721f33c933d2b80242cd21b44033d2b9d401cd21 }


condition:
	$a0
}