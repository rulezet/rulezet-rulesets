rule Win_Trojan_Companion_32
{
strings:
	$a0 = { 0900b02ef2aec705434fc645024dba7eeab43cb92300cd21720b93b440b9e000ba0001cd21 }


condition:
	$a0
}