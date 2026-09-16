rule Win_Trojan_Startpage_441
{
strings:
	$a0 = { 688cee4500b9acee4500bac0ee4500b802000080e80cfeffff33c05a59596489106846ee4500 }


condition:
	$a0
}