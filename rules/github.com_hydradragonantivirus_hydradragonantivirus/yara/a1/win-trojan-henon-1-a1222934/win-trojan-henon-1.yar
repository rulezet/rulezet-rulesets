rule Win_Trojan_Henon_1
{
strings:
	$a0 = { 961701b9d102cd21b801578b8ea2028b96a402cd21 }


condition:
	$a0
}