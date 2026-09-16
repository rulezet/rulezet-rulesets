rule Win_Trojan_NWO_1
{
strings:
	$a0 = { 81ed03012e8c8647020e1fb8f1ffcd213df1ff7503eb5490b82135cd212e899eec022e8c86ee0233c0500726ff0e13 }


condition:
	$a0
}