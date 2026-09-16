rule Win_Trojan_Facade_2
{
strings:
	$a0 = { 33c08ed88ec0fa8ed0bc007cfb8bf48bdc1e5656be4c00bf927da5a55e33ffcd122d0100a31304b106d3e08ec0b8 }


condition:
	$a0
}