rule Win_Trojan_E266_1
{
strings:
	$a0 = { 8b2c444481ed030081fcadde7510060e078db624048dbed4002ea52ea507601e0633c0508ed8a184003d0b0275 }


condition:
	$a0
}