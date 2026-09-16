rule Win_Trojan_Marata_1
{
strings:
	$a0 = { 2e4f70656e5465787446696c6528582e506174682c322c5472756529 }


condition:
	$a0
}