rule Win_Trojan_Feliz_3
{
strings:
	$a0 = { 74f989861e00e89b005bb440b93b048bd5cd21e88e00e8ae00b440b91a008d963704cd }


condition:
	$a0
}