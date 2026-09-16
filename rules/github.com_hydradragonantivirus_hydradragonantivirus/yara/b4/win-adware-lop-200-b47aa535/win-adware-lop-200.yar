rule Win_Adware_Lop_200
{
strings:
	$a0 = { 8eb1307463f63504ef677c9ad30c26ced7999ac90da0aa784514ce97209e8f897b65373f074b9216967838ff2b6e5f34c72c4c7ed77d2825cbc74ad6 }


condition:
	$a0
}