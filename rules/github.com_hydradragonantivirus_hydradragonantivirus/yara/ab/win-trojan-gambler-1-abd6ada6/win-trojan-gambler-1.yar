rule Win_Trojan_Gambler_1
{
strings:
	$a0 = { 803f55743da1130448b106d3e0a39c020e1eb87602b9200150cbb90100b80a03ba8000fbcd13ea }


condition:
	$a0
}