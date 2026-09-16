rule Win_Trojan_Trojan_350
{
strings:
	$a0 = { 8d963f02e8330080beb40207730ab43b8d964502cd2173e88db67302c6045c }


condition:
	$a0
}