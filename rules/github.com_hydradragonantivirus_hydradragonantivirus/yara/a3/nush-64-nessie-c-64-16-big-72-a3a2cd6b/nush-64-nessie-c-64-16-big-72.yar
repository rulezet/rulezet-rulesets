rule Nush_64___Nessie_C_64__16_big_72_
{
strings:
	$a0 = { ac258a93243d262ef887c4f28e369fa17dc06a296d8434bda267cc1504feb94adf2440ef96da905fd631aa624d1570cb753345fc5337d25ea9261c7b5f124ecc3c8628dbfc017cb1 }

condition:
	$a0
}