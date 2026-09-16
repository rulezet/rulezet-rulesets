rule Win_Trojan_Lala_1
{
strings:
	$a0 = { 0a0d008db62100b82601ffd08db62900b82601ffd08db63800b82601ffd08db64700b82601 }


condition:
	$a0
}