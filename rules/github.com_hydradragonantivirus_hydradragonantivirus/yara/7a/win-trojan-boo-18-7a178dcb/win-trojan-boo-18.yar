rule Win_Trojan_BOO_18
{
strings:
	$a0 = { a11304d3e02de0078ec0832e130403be007c8bfeb90001f3a506b8707c50cb061fbb00728b0e }


condition:
	$a0
}