rule Win_Spyware_Banker_1375
{
strings:
	$a0 = { decb56e82af88e3025b0b5ea9476a30ffe0d3c92568248c2034ad1722b5fab4547bac501c3cff9a1918a0031e7e74f48a0d1de550f5dda151cfc2cdce4d0362f2accb7e6 }


condition:
	$a0
}