rule Win_Trojan_Femo_1
{
strings:
	$a0 = { 68ff03000033ff5057ff157cb1001085c074148b0d74e300106808d10010e83dcdffff85c07507 }


condition:
	$a0
}