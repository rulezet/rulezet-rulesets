rule Win_Trojan_Rushhour_1
{
strings:
	$a0 = { 067c0000a172003d00487450c6067e0701be0001bf8000b98000f3a4ba5c00b415cd2181fe2a1c }


condition:
	$a0
}