rule Win_Trojan_Flax_1
{
strings:
	$a0 = { 6a00e809fdffff83c40489c050e82efdffff83c40466837de6007515e8fffbffff89c189c8bbffff000099f7fb668955e6 }

	$a1 = { 617468206f6e20666c617865 }


condition:
	$a0 and $a1
}