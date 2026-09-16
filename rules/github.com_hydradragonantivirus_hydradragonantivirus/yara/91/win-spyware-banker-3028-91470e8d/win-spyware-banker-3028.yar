rule Win_Spyware_Banker_3028
{
strings:
	$a0 = { 88068c7e2f95f5efd19e30b51a307b3759119fe6f0217348915652567d18f230b225cb6cf6b555331749e4c794 }


condition:
	$a0
}