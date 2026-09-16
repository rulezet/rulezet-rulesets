rule Win_Trojan_Jasmine_2
{
strings:
	$a0 = { 02b90500ba0000cd26b44eba030133c9cd21ba9e00b43db001cd218bd8b440ba0001b90e01cd21 }


condition:
	$a0
}