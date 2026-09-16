rule Win_Trojan_Fayte_1
{
strings:
	$a0 = { 024d5a7457803e2002467450b8004233d233c9cd21b4405981c11d01ba0001cd218b0e1902 }


condition:
	$a0
}