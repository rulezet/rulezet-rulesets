rule Win_Trojan_Small_165
{
strings:
	$a0 = { 83ee03061eb82135cd21899ca1008c84a300b92100510733ff26803de8741056b1bdfcf3a45e061fba4000b425cd21 }


condition:
	$a0
}