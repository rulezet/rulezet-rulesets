rule Win_Trojan_Boot_10
{
strings:
	$a0 = { 1a80fe12751a5abb00088ec3b90100b809039c0ee8b9fffec580fd0375f1 }


condition:
	$a0
}